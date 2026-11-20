use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};

/// Rename a secret in a config file
///
/// Renames OLD to NEW in the config file in the current directory, or the
/// global config with `--global`, keeping the secret's value, provider and
/// other fields, plus comments and formatting. Nothing is decrypted, and a
/// secret stored at a remote provider keeps pointing at the same remote item.
/// Fails if NEW already exists in that file.
#[derive(Debug, usage_rs::Args)]
#[usage(alias("mv"))]
#[usage(
    example(
        "fnox rename OLD_TOKEN NEW_TOKEN --dry-run",
        header = "Preview the change"
    ),
    example(
        "fnox rename MY_SERVICE_API_KEY MYSERVICE_API_KEY",
        header = "Rename a secret"
    ),
    example(
        "fnox -P staging rename OLD_TOKEN NEW_TOKEN",
        header = "Rename it in the staging profile"
    ),
    after_long_help = "See also:\n- Config files: https://fnox.jdx.dev/guide/config-files"
)]
pub struct RenameCommand {
    /// Current name of the secret
    pub old: String,

    /// New name for the secret
    pub new: String,

    /// Rename in the global config file (`~/.config/fnox/config.toml`)
    #[usage(short = 'g', long)]
    pub global: bool,

    /// Show what would be renamed without changing the file
    #[usage(short = 'n', long)]
    pub dry_run: bool,
}

impl RenameCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        if self.old == self.new {
            return Err(FnoxError::Config(
                "The old and new secret names are the same".into(),
            ));
        }
        let profile = Config::get_profiles(cli.profile.as_slice());
        let write_profile = Config::resolve_write_profile(&profile, cli.write_profile.as_deref())?;
        tracing::debug!(
            "Renaming secret '{}' to '{}' in profile '{}'",
            self.old,
            self.new,
            write_profile
        );

        let target_path = if self.global {
            Config::global_config_path()
        } else {
            let current_dir = std::env::current_dir().map_err(|e| {
                FnoxError::Config(format!("Failed to get current directory: {}", e))
            })?;
            if cli.config == std::path::Path::new(crate::config::DEFAULT_CONFIG_FILENAME) {
                crate::commands::set::find_default_config(
                    &current_dir,
                    &profile,
                    &write_profile,
                    cli.walk_up,
                )
            } else {
                current_dir.join(&cli.config)
            }
        };

        if !target_path.exists() {
            return Err(FnoxError::ConfigFileNotFound { path: target_path });
        }

        let config = Config::load(&target_path)?;
        let secrets = if write_profile != "default" {
            config.profiles.get(&write_profile).map(|p| &p.secrets)
        } else {
            Some(&config.secrets)
        };
        let not_found = || FnoxError::SecretNotFound {
            key: self.old.clone(),
            profile: write_profile.clone(),
            config_path: Some(target_path.clone()),
            suggestion: None,
        };
        let secrets = secrets.ok_or_else(not_found)?;
        if !secrets.contains_key(&self.old) {
            return Err(not_found());
        }
        if secrets.contains_key(&self.new) {
            return Err(FnoxError::Config(format!(
                "Secret '{}' already exists in {}",
                self.new,
                target_path.display()
            )));
        }

        let styled_old = console::style(&self.old).cyan();
        let styled_new = console::style(&self.new).cyan();
        let global_suffix = if self.global { " (global)" } else { "" };
        let profile_suffix = if write_profile == "default" {
            String::new()
        } else {
            format!(" in profile {}", console::style(&write_profile).magenta())
        };

        if self.dry_run {
            let label = console::style("[dry-run]").yellow().bold();
            let styled_path = console::style(target_path.display()).dim();
            println!(
                "{label} Would rename secret {styled_old} to {styled_new}{profile_suffix}{global_suffix} in {styled_path}"
            );
            return Ok(());
        }

        if !Config::rename_secret_in_source(&self.old, &self.new, &write_profile, &target_path)? {
            return Err(not_found());
        }
        let check = console::style("✓").green();
        println!(
            "{check} Renamed secret {styled_old} to {styled_new}{profile_suffix}{global_suffix}"
        );
        Ok(())
    }
}
