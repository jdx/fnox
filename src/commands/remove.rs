use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use clap::Args;

#[derive(Debug, Args)]
#[command(visible_aliases = ["rm", "delete"])]
pub struct RemoveCommand {
    /// Secret key to remove
    pub key: String,

    /// Remove from the global config file (~/.config/fnox/config.toml)
    #[arg(short = 'g', long)]
    pub global: bool,

    /// Show what would be removed without making changes
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

impl RemoveCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Removing secret '{}' from profile '{}'", self.key, profile);

        // Determine the target config file
        let target_path = if self.global {
            Config::global_config_path()
        } else {
            let current_dir = std::env::current_dir().map_err(|e| {
                FnoxError::Config(format!("Failed to get current directory: {}", e))
            })?;
            current_dir.join(&cli.config)
        };

        // Load the target config file directly (not the merged config)
        if !target_path.exists() {
            return Err(FnoxError::ConfigFileNotFound {
                path: target_path.clone(),
            });
        }

        // Check the secret exists before attempting removal
        let config = Config::load(&target_path)?;
        let profile_secrets = config.get_secrets(&profile)?;

        if !profile_secrets.contains_key(&self.key) {
            return Err(FnoxError::SecretNotFound {
                key: self.key.clone(),
                profile: profile.to_string(),
                config_path: Some(target_path),
                suggestion: None,
            });
        }

        if self.dry_run {
            let dry_run_label = console::style("[dry-run]").yellow().bold();
            let styled_key = console::style(&self.key).cyan();
            let styled_profile = console::style(&profile).magenta();
            let styled_path = console::style(target_path.display()).dim();
            let global_suffix = if self.global { " (global)" } else { "" };
            if profile == "default" {
                println!(
                    "{dry_run_label} Would remove secret {styled_key}{global_suffix} from {styled_path}"
                );
            } else {
                println!(
                    "{dry_run_label} Would remove secret {styled_key} from profile {styled_profile}{global_suffix} from {styled_path}"
                );
            }
        } else {
            // Remove secret directly from the TOML document, preserving comments
            let removed = Config::remove_secret_from_source(&self.key, &profile, &target_path)?;
            if !removed {
                return Err(FnoxError::SecretNotFound {
                    key: self.key.clone(),
                    profile: profile.to_string(),
                    config_path: Some(target_path),
                    suggestion: None,
                });
            }
            let check = console::style("✓").green();
            let styled_key = console::style(&self.key).cyan();
            let styled_profile = console::style(&profile).magenta();
            let global_suffix = if self.global { " (global)" } else { "" };
            if profile == "default" {
                println!("{check} Removed secret {styled_key}{global_suffix}");
            } else {
                println!(
                    "{check} Removed secret {styled_key} from profile {styled_profile}{global_suffix}"
                );
            }
        }

        Ok(())
    }
}
