use crate::config::Config;
use crate::env_diff::{EnvDiff, EnvDiffOperation};
use crate::hook_env::{self, HookEnvSession, PREV_SESSION};
use crate::settings::Settings;
use crate::shell;
use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;

/// Output mode for shell integration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    None,
    Normal,
    Debug,
}

impl OutputMode {
    fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "none" | "off" | "false" | "0" => Self::None,
            "debug" | "verbose" => Self::Debug,
            _ => Self::Normal, // default to normal
        }
    }

    fn should_show_summary(self) -> bool {
        matches!(self, Self::Normal | Self::Debug)
    }

    fn should_show_debug(self) -> bool {
        matches!(self, Self::Debug)
    }
}

#[derive(Debug, Parser)]
#[command(about = "Internal command used by shell hooks to load secrets")]
pub struct HookEnvCommand {
    /// Shell type (bash, zsh, fish)
    #[arg(short = 's', long)]
    pub shell: Option<String>,
}

impl HookEnvCommand {
    pub async fn run(&self) -> Result<()> {
        // Get settings for output mode
        let settings =
            Settings::try_get().map_err(|e| anyhow::anyhow!("Failed to get settings: {}", e))?;
        let output_mode = OutputMode::from_string(&settings.shell_integration_output);

        // Detect shell
        let shell_name = match &self.shell {
            Some(s) => s.clone(),
            None => shell::detect_shell().unwrap_or_else(|| "bash".to_string()),
        };

        let shell = shell::get_shell(Some(&shell_name))?;

        if output_mode.should_show_debug() {
            eprintln!(
                "fnox: hook-env running in {:?}",
                std::env::current_dir().ok()
            );
        }

        // Check if we can exit early (optimization)
        if hook_env::should_exit_early() {
            if output_mode.should_show_debug() {
                eprintln!("fnox: early exit - no changes detected");
            }
            // Nothing changed, no output needed
            return Ok(());
        }

        if output_mode.should_show_debug() {
            eprintln!("fnox: changes detected, loading secrets");
        }

        // Find fnox.toml in current or parent directories
        let config_path = hook_env::find_config();

        let mut output = String::new();

        // Load secrets if config exists
        let loaded_secrets = if let Some(ref path) = config_path {
            match load_secrets_from_config(path).await {
                Ok(secrets) => secrets,
                Err(e) => {
                    // Log error but don't fail the shell hook
                    tracing::warn!("failed to load secrets: {}", e);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        // Calculate diff from previous session
        let old_secrets = PREV_SESSION.loaded_secrets.clone();
        let env_diff = EnvDiff::new(old_secrets, loaded_secrets.clone());

        // Display summary of changes if enabled
        if output_mode.should_show_summary() && env_diff.has_changes() {
            display_changes(&env_diff, output_mode);
        }

        // Generate shell code for environment changes
        if env_diff.has_changes() {
            for operation in env_diff.operations() {
                match operation {
                    EnvDiffOperation::Set(key, value) => {
                        output.push_str(&shell.set_env(&key, &value));
                    }
                    EnvDiffOperation::Remove(key) => {
                        output.push_str(&shell.unset_env(&key));
                    }
                }
            }
        }

        // Create new session
        let current_dir = std::env::current_dir().ok();
        let session = HookEnvSession::new(current_dir, config_path, loaded_secrets)?;

        // Export session state for next invocation
        let session_encoded = session.encode()?;
        output.push_str(&shell.set_env("__FNOX_SESSION", &session_encoded));

        // Export diff state for potential rollback
        let diff_encoded = env_diff.encode()?;
        output.push_str(&shell.set_env("__FNOX_DIFF", &diff_encoded));

        print!("{}", output);

        Ok(())
    }
}

/// Load all secrets from a fnox.toml config file
async fn load_secrets_from_config(
    config_path: &std::path::Path,
) -> Result<HashMap<String, String>> {
    use crate::secret_resolver::resolve_secrets_batch;

    let config =
        Config::load(config_path).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let settings =
        Settings::try_get().map_err(|e| anyhow::anyhow!("Failed to get settings: {}", e))?;

    // Get the active profile
    let profile_name = &settings.profile;

    // Get secrets for the profile using the Config method (inherits top-level secrets)
    let secrets = config
        .get_secrets(profile_name)
        .map_err(|e| anyhow::anyhow!("Failed to get secrets: {}", e))?;

    let age_key_file = settings.age_key_file.as_deref();

    // Use batch resolution for better performance
    let resolved = match resolve_secrets_batch(&config, profile_name, &secrets, age_key_file).await
    {
        Ok(r) => r,
        Err(e) => {
            // Log error but don't fail the shell hook
            tracing::warn!("failed to resolve secrets: {}", e);
            return Ok(HashMap::new());
        }
    };

    // Convert to HashMap, filtering out None values
    let mut loaded_secrets = HashMap::new();
    for (key, value) in resolved {
        if let Some(value) = value {
            loaded_secrets.insert(key, value);
        }
    }

    Ok(loaded_secrets)
}

/// Display a summary of environment changes
fn display_changes(env_diff: &EnvDiff, mode: OutputMode) {
    use console::{Style, Term};

    let term = Term::stderr();
    let cyan = Style::new().cyan().for_stderr();
    let dim = Style::new().dim().for_stderr();

    let operations = env_diff.operations();
    let mut added_keys = Vec::new();
    let mut removed_keys = Vec::new();

    for op in operations {
        match op {
            EnvDiffOperation::Set(key, _value) => {
                added_keys.push(key.clone());
            }
            EnvDiffOperation::Remove(key) => {
                removed_keys.push(key.clone());
            }
        }
    }

    if mode.should_show_debug() {
        // Debug mode: show each secret on its own line
        if !added_keys.is_empty() {
            let _ = term.write_line(&format!("fnox: loaded {} secret(s):", added_keys.len()));
            for key in &added_keys {
                let _ = term.write_line(&format!("  + {}", cyan.apply_to(key)));
            }
        }
        if !removed_keys.is_empty() {
            let _ = term.write_line(&format!("fnox: unloaded {} secret(s):", removed_keys.len()));
            for key in &removed_keys {
                let _ = term.write_line(&format!("  - {}", cyan.apply_to(key)));
            }
        }
    } else {
        // Normal mode: compact single-line summary with keys
        let term_width = term.size().1 as usize;

        let mut parts = Vec::new();

        if !added_keys.is_empty() {
            let count = format!("+{}", added_keys.len());
            let keys = added_keys
                .iter()
                .map(|k| cyan.apply_to(k).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            parts.push((count, keys, added_keys.len()));
        }

        if !removed_keys.is_empty() {
            let count = format!("-{}", removed_keys.len());
            let keys = removed_keys
                .iter()
                .map(|k| cyan.apply_to(k).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            parts.push((count, keys, removed_keys.len()));
        }

        if !parts.is_empty() {
            // Build the full line and truncate if needed
            let counts = parts
                .iter()
                .map(|(c, _, _)| c.clone())
                .collect::<Vec<_>>()
                .join(" ");

            let all_keys = parts
                .iter()
                .map(|(_, k, _)| k.clone())
                .collect::<Vec<_>>()
                .join(", ");

            // "fnox: +N -M " prefix length (without ANSI codes)
            let prefix = format!("fnox: {} ", counts);
            let prefix_len = prefix.len();
            let prefix = console::style(prefix).dim().for_stderr();

            // Calculate available space for keys
            // Reserve some space for potential "..." if we need to truncate
            let available = if term_width > prefix_len + 10 {
                term_width - prefix_len - 4 // Reserve 4 chars for ", ..."
            } else {
                40 // Minimum reasonable width
            };

            // Strip ANSI codes to measure actual length
            let keys_plain: String = added_keys
                .iter()
                .chain(removed_keys.iter())
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            if keys_plain.len() <= available {
                // Fits on one line
                let _ = term.write_line(&format!("{}{}", prefix, all_keys));
            } else {
                // Need to truncate
                let mut truncated_keys = Vec::new();
                let mut current_len = 0;

                for key in added_keys.iter().chain(removed_keys.iter()) {
                    let key_len = key.len() + 2; // +2 for ", "
                    if current_len + key_len > available {
                        break;
                    }
                    truncated_keys.push(cyan.apply_to(key).to_string());
                    current_len += key_len;
                }

                if !truncated_keys.is_empty() {
                    let _ = term.write_line(&format!(
                        "{}{}, {}",
                        prefix,
                        truncated_keys.join(", "),
                        dim.apply_to("...")
                    ));
                } else {
                    // Even first key doesn't fit, just show counts
                    let _ = term.write_line(&format!("{}{}", prefix, dim.apply_to("...")));
                }
            }
        }
    }
}
