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
            return Err(miette::miette!(
                "Config file '{}' not found",
                target_path.display()
            ))?;
        }

        let mut config = Config::load(&target_path)?;

        // Get the profile secrets
        let profile_secrets = config.get_secrets_mut(&profile);

        if profile_secrets.shift_remove(&self.key).is_some() {
            config.save(&target_path)?;
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
        } else {
            Err(miette::miette!(
                "Secret '{}' not found in profile '{}'",
                self.key,
                profile
            ))?;
        }

        Ok(())
    }
}
