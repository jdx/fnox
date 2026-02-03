use crate::config::Config;
use crate::hook_env::{self, HookEnvSession, PREV_SESSION};
use crate::settings::Settings;
use crate::shell;
use crate::temp_file_secrets::create_persistent_secret_file;
use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::fs;

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
        let loaded_data = if config_path.is_some() {
            match load_secrets_from_config().await {
                Ok(data) => data,
                Err(e) => {
                    // Log error but don't fail the shell hook
                    tracing::warn!("failed to load secrets: {}", e);
                    LoadedSecrets {
                        secrets: HashMap::new(),
                        temp_files: HashMap::new(),
                    }
                }
            }
        } else {
            LoadedSecrets {
                secrets: HashMap::new(),
                temp_files: HashMap::new(),
            }
        };

        // Clean up old temp files that are no longer needed
        cleanup_old_temp_files(&PREV_SESSION.temp_files, &loaded_data.temp_files);

        // Calculate changes from previous session using hashes
        let (added, removed) = calculate_changes(&PREV_SESSION.secret_hashes, &loaded_data.secrets);

        // Display summary of changes if enabled
        if output_mode.should_show_summary() && (!added.is_empty() || !removed.is_empty()) {
            display_changes(&added, &removed, output_mode);
        }

        // Generate shell code for environment changes
        // Set new/updated secrets
        for (key, value) in &added {
            output.push_str(&shell.set_env(key, value));
        }
        // Remove secrets no longer in config
        for key in &removed {
            output.push_str(&shell.unset_env(key));
        }

        // Create new session
        let current_dir = std::env::current_dir().ok();
        let session = HookEnvSession::new(
            current_dir,
            config_path,
            loaded_data.secrets,
            loaded_data.temp_files,
        )?;

        // Export session state for next invocation
        let session_encoded = session.encode()?;
        output.push_str(&shell.set_env("__FNOX_SESSION", &session_encoded));

        print!("{}", output);

        Ok(())
    }
}

/// Calculate which secrets were added/changed or removed by comparing hashes
fn calculate_changes(
    old_hashes: &indexmap::IndexMap<String, String>,
    new_secrets: &HashMap<String, String>,
) -> (Vec<(String, String)>, Vec<String>) {
    use crate::hook_env::{PREV_SESSION, hash_secret_value_with_session};

    let mut added = Vec::new();
    let mut removed = Vec::new();

    // Find additions and changes by comparing hashes
    for (key, new_value) in new_secrets {
        // Use the previous session's hash_key for comparison
        let new_hash = hash_secret_value_with_session(&PREV_SESSION, key, new_value);
        match old_hashes.get(key) {
            Some(old_hash) if old_hash == &new_hash => {
                // Hash matches, no change
            }
            _ => {
                // New or changed value (hash differs or key is new)
                added.push((key.clone(), new_value.clone()));
            }
        }
    }

    // Find removals - keys that were in old session but not in new
    for key in old_hashes.keys() {
        if !new_secrets.contains_key(key) {
            removed.push(key.clone());
        }
    }

    (added, removed)
}

/// Result of loading secrets with file-based information
struct LoadedSecrets {
    /// Secret values (or file paths for file-based secrets)
    secrets: HashMap<String, String>,
    /// Temp file paths for file-based secrets
    temp_files: HashMap<String, String>,
}

/// Load all secrets from a fnox.toml config file
async fn load_secrets_from_config() -> Result<LoadedSecrets> {
    use crate::secret_resolver::resolve_secrets_batch;

    // Use load_smart to ensure provider inheritance from parent configs
    // This handles fnox.toml and fnox.local.toml with proper recursion
    let settings =
        Settings::try_get().map_err(|e| anyhow::anyhow!("Failed to get settings: {}", e))?;
    let filenames = crate::config::all_config_filenames(Some(&settings.profile));
    let mut last_error = None;
    let mut config = None;
    for filename in &filenames {
        match Config::load_smart(filename) {
            Ok(c) => {
                config = Some(c);
                break;
            }
            Err(e) => {
                // Only store parse errors (not "file not found" errors)
                // to show detailed error messages for actual config issues
                let is_not_found = matches!(&e, crate::error::FnoxError::ConfigNotFound { .. });
                if !is_not_found {
                    last_error = Some(e);
                }
            }
        }
    }
    let config = match (config, last_error) {
        (Some(c), _) => c,
        (None, Some(e)) => return Err(anyhow::anyhow!("{}", e)),
        (None, None) => {
            return Err(anyhow::anyhow!(
                "No configuration file found (tried: {})",
                filenames.join(", ")
            ));
        }
    };

    // Get the active profile (settings was already loaded above)
    let profile_name = &settings.profile;

    // Get secrets for the profile using the Config method (inherits top-level secrets)
    let profile_secrets = config
        .get_secrets(profile_name)
        .map_err(|e| anyhow::anyhow!("Failed to get secrets: {}", e))?;

    // Use batch resolution for better performance
    let resolved = match resolve_secrets_batch(&config, profile_name, &profile_secrets).await {
        Ok(r) => r,
        Err(e) => {
            // Log error but don't fail the shell hook
            tracing::warn!("failed to resolve secrets: {}", e);
            return Ok(LoadedSecrets {
                secrets: HashMap::new(),
                temp_files: HashMap::new(),
            });
        }
    };

    // Process secrets: create temp files for file-based secrets
    let mut loaded_secrets = HashMap::new();
    let mut temp_files = HashMap::new();

    for (key, value_opt) in resolved {
        if let Some(value) = value_opt {
            // Check if this secret should be file-based
            if let Some(secret_config) = profile_secrets.get(&key) {
                if secret_config.as_file {
                    // Create a persistent temp file for this secret
                    match create_persistent_secret_file("fnox-hook-", &key, &value) {
                        Ok(file_path) => {
                            // Store the file path as the "value" to set in env
                            loaded_secrets.insert(key.clone(), file_path.clone());
                            temp_files.insert(key, file_path);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "failed to create temp file for secret '{}': {}",
                                key,
                                e
                            );
                        }
                    }
                } else {
                    // Regular secret - store value directly
                    loaded_secrets.insert(key, value);
                }
            } else {
                loaded_secrets.insert(key, value);
            }
        }
    }

    Ok(LoadedSecrets {
        secrets: loaded_secrets,
        temp_files,
    })
}

/// Clean up old temp files that are no longer needed
fn cleanup_old_temp_files(
    old_files: &HashMap<String, String>,
    new_files: &HashMap<String, String>,
) {
    for (key, old_path) in old_files {
        // Only delete if this secret is no longer file-based or has a different path
        if !new_files.contains_key(key) || new_files.get(key) != Some(old_path) {
            if let Err(e) = fs::remove_file(old_path) {
                // Log but don't fail - file might already be deleted
                tracing::debug!("failed to clean up temp file for '{}': {}", key, e);
            } else {
                tracing::debug!("cleaned up temp file for secret '{}'", key);
            }
        }
    }
}

/// Display a summary of environment changes
fn display_changes(added: &[(String, String)], removed: &[String], mode: OutputMode) {
    use console::{Style, Term};

    let term = Term::stderr();
    let cyan = Style::new().cyan().for_stderr();
    let dim = Style::new().dim().for_stderr();

    let added_keys: Vec<String> = added.iter().map(|(k, _)| k.clone()).collect();
    let removed_keys: Vec<String> = removed.to_vec();

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
