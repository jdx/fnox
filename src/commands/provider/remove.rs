use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use clap::Args;

#[derive(Debug, Args)]
#[command(visible_aliases = ["rm", "delete"])]
pub struct RemoveCommand {
    /// Provider name
    pub provider: String,

    /// Remove from the global config file (~/.config/fnox/config.toml)
    #[arg(short = 'g', long)]
    pub global: bool,
}

impl RemoveCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        tracing::debug!("Removing provider '{}'", self.provider);
        // Provider remove only respects explicit CLI --profile flags, matching
        // provider add's behavior (see add.rs).
        let profiles = Config::normalize_profiles(&cli.profile);
        let write_profile = Config::resolve_write_profile(&profiles, cli.write_profile.as_deref())?;

        // Determine the target config file
        let target_path = if self.global {
            Config::global_config_path()
        } else {
            let current_dir = std::env::current_dir().map_err(|e| {
                FnoxError::Config(format!("Failed to get current directory: {}", e))
            })?;
            if cli.config == std::path::Path::new(crate::config::DEFAULT_CONFIG_FILENAME) {
                crate::config::find_local_config(&current_dir, std::slice::from_ref(&write_profile))
            } else {
                current_dir.join(&cli.config)
            }
        };

        // Load the target config file directly
        if !target_path.exists() {
            return Err(FnoxError::Config(format!(
                "Config file '{}' not found",
                target_path.display()
            )));
        }

        let mut config = Config::load(&target_path)?;

        let removed = if self.global || write_profile == "default" {
            config.providers.shift_remove(&self.provider).is_some()
        } else {
            config
                .profiles
                .get_mut(&write_profile)
                .and_then(|profile| profile.providers.shift_remove(&self.provider))
                .is_some()
        };

        if removed {
            config.save(&target_path)?;
            let global_suffix = if self.global { " (global)" } else { "" };
            println!("✓ Removed provider '{}'{}", self.provider, global_suffix);
        } else {
            return Err(FnoxError::Config(format!(
                "Provider '{}' not found",
                self.provider
            )));
        }

        Ok(())
    }
}
