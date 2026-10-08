use crate::commands::Cli;
use crate::config::{self, Config};
use crate::error::{FnoxError, Result};
use crate::secret_file::SecretFileFormat;
use console;
use indexmap::IndexMap;
use regex::Regex;
use std::io::{self, Read};
use std::{collections::HashMap, path::PathBuf};
use strum::{Display, EnumString, VariantNames};

/// Supported import formats
#[derive(Debug, Clone, Copy, usage_rs::ValueEnum, Display, EnumString, VariantNames)]
#[strum(serialize_all = "lowercase")]
pub enum ImportFormat {
    /// Environment variable format (KEY=value)
    Env,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// TOML format
    Toml,
}

/// Import secrets from various sources
#[derive(usage_rs::Args)]
#[usage(alias("im"))]
pub struct ImportCommand {
    /// Import source format
    #[usage(arg, default = "env", value_enum)]
    format: ImportFormat,

    /// Skip confirmation prompts
    #[usage(short, long)]
    force: bool,

    /// Import to the global config file (~/.config/fnox/config.toml)
    #[usage(short = 'g', long)]
    global: bool,

    /// Source file or path to import from (default: stdin)
    #[usage(short = 'i', long)]
    input: Option<PathBuf>,

    /// Show what would be imported without making changes
    #[usage(short = 'n', long)]
    dry_run: bool,

    /// Provider to use for encrypting/storing imported secrets (required)
    #[usage(short = 'p', long)]
    provider: String,

    /// Only import matching secrets (regex pattern)
    #[usage(long)]
    filter: Option<String>,

    /// Prefix to add to imported secret names
    #[usage(long)]
    prefix: Option<String>,
}

impl ImportCommand {
    pub async fn run(&self, cli: &Cli, merged_config: Config) -> Result<()> {
        let profile = Config::get_profiles(cli.profile.as_slice());
        let write_profile = Config::resolve_write_profile(&profile, cli.write_profile.as_deref())?;
        tracing::debug!(
            "Importing secrets in {} format into profile '{}'",
            self.format,
            write_profile
        );

        let input = self.read_input()?;
        let mut secrets = self.parse_input(&input)?;

        // When importing from stdin, --force or --dry-run is required because stdin is consumed
        // by read_input() and won't be available for the confirmation prompt
        // (dry-run doesn't need confirmation since it doesn't modify anything)
        if self.input.is_none() && !self.force && !self.dry_run {
            return Err(FnoxError::ImportStdinRequiresForce);
        }

        // Apply filter if specified
        if let Some(ref filter) = self.filter {
            let regex = Regex::new(filter).map_err(|e| FnoxError::InvalidRegexFilter {
                pattern: filter.clone(),
                details: e.to_string(),
            })?;
            secrets.retain(|key, _| regex.is_match(key));
        }

        // Apply prefix if specified
        if let Some(ref prefix) = self.prefix {
            let mut prefixed_secrets = HashMap::new();
            for (key, value) in secrets {
                let prefixed_key = format!("{}{}", prefix, key);
                prefixed_secrets.insert(prefixed_key, value);
            }
            secrets = prefixed_secrets;
        }

        // Reject names after filtering and prefixing, before provider lookup or
        // encryption can perform any side effects. Otherwise import could
        // persist a config that fails as soon as secrets are resolved.
        let mut secret_names = secrets.keys().collect::<Vec<_>>();
        secret_names.sort_unstable();
        for key in secret_names {
            config::validate_secret_name(key)?;
        }

        if secrets.is_empty() {
            println!("No secrets to import");
            return Ok(());
        }

        // Verify provider exists (use merged config to find providers from any source)
        let providers = merged_config.get_providers(&profile)?;
        let provider_config =
            providers
                .get(&self.provider)
                .ok_or_else(|| FnoxError::ProviderNotConfigured {
                    provider: self.provider.clone(),
                    profile: Config::display_profiles(&profile),
                    config_path: None,
                    suggestion: None,
                })?;

        // Get provider and validate capabilities (needed for both dry-run and actual import)
        let provider = crate::providers::get_provider_resolved(
            &merged_config,
            &profile,
            &self.provider,
            provider_config,
        )
        .await?;
        let capabilities = provider.capabilities();
        let is_encryption_provider =
            capabilities.contains(&crate::providers::ProviderCapability::Encryption);
        let is_remote_storage_provider =
            capabilities.contains(&crate::providers::ProviderCapability::RemoteStorage);

        // Validate that provider supports import (encryption capability required)
        if !is_encryption_provider {
            if is_remote_storage_provider {
                return Err(FnoxError::ImportProviderUnsupported {
                    provider: self.provider.clone(),
                    help: "Remote storage providers are not yet supported for import. Use an encryption provider like 'age' instead.".to_string(),
                });
            } else {
                return Err(FnoxError::ImportProviderUnsupported {
                    provider: self.provider.clone(),
                    help: "Provider does not support encryption or remote storage".to_string(),
                });
            }
        }

        // In dry-run mode, show what would be imported and exit
        // (provider and capability validation above ensures dry-run fails on invalid provider)
        if self.dry_run {
            let dry_run_label = console::style("[dry-run]").yellow().bold();
            let styled_profile = console::style(&write_profile).magenta();
            let styled_provider = console::style(&self.provider).green();
            let global_suffix = if self.global { " (global)" } else { "" };

            println!(
                "{dry_run_label} Would import {} secrets into profile {styled_profile} using provider {styled_provider}{global_suffix}:",
                secrets.len()
            );
            for key in secrets.keys() {
                println!("  {}", console::style(key).cyan());
            }
            return Ok(());
        }

        // Confirm import unless forced
        if !self.force {
            println!(
                "\nReady to import {} secrets into profile '{}':",
                secrets.len(),
                write_profile
            );
            for key in secrets.keys().take(10) {
                println!("  {}", key);
            }
            if secrets.len() > 10 {
                println!("  ... and {} more", secrets.len() - 10);
            }

            println!("\nContinue? [y/N]");
            let mut response = String::new();
            io::stdin()
                .read_line(&mut response)
                .map_err(|e| FnoxError::StdinReadFailed { source: e })?;

            if !response.trim().to_lowercase().starts_with('y') {
                println!("Import cancelled");
                return Ok(());
            }
        }

        // Determine the target config file path
        let target_path = if self.global {
            Config::global_config_path()
        } else {
            // Match set.rs: use find_local_config when --config is the default,
            // so profile-specific files (fnox.<profile>.toml) are found.
            if cli.config == std::path::Path::new(config::DEFAULT_CONFIG_FILENAME) {
                let current_dir = std::env::current_dir().map_err(|e| {
                    FnoxError::Config(format!("Failed to get current directory: {}", e))
                })?;
                config::find_local_config(&current_dir, std::slice::from_ref(&write_profile))
            } else {
                cli.config.clone()
            }
        };

        // Explicit project paths may live under `.config/`; create their
        // parent directory just as we do for the global config.
        if let Some(parent) = target_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| FnoxError::CreateDirFailed {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        // Load existing target config to preserve metadata on re-import
        let mut existing_config = if target_path.exists() {
            Some(Config::load(&target_path)?)
        } else {
            None
        };

        // Build the secrets to import (encrypt each value)
        let mut import_secrets = IndexMap::new();
        let total_secrets = secrets.len();

        for (key, value) in secrets {
            // Start from existing config if key already exists, to preserve metadata
            // (description, if_missing, default, as_file, etc.)
            let mut secret_config = existing_config
                .as_mut()
                .and_then(|c| c.get_secrets_mut(&profile).shift_remove(&key))
                .unwrap_or_default();

            // Set the provider
            secret_config.set_provider(Some(self.provider.clone()));

            // Encrypt the value (provider already validated as encryption provider)
            match provider.encrypt(&value).await {
                Ok(encrypted) => {
                    secret_config.set_value(Some(encrypted));
                }
                Err(e) => {
                    return Err(FnoxError::ImportEncryptionFailed {
                        key: key.clone(),
                        provider: self.provider.clone(),
                        details: e.to_string(),
                    });
                }
            }

            import_secrets.insert(key, secret_config);
        }

        // Save secrets directly to the TOML document, preserving comments
        Config::save_secrets_to_source(&import_secrets, &write_profile, &target_path)?;

        let global_suffix = if self.global { " (global)" } else { "" };
        println!(
            "✓ Imported {} secrets into profile '{}' using provider '{}'{}",
            total_secrets, write_profile, self.provider, global_suffix
        );

        Ok(())
    }

    fn read_input(&self) -> Result<String> {
        if let Some(ref input_path) = self.input {
            // Read from specified file
            let input =
                std::fs::read_to_string(input_path).map_err(|e| FnoxError::ImportReadFailed {
                    path: input_path.clone(),
                    source: e,
                })?;
            Ok(input)
        } else {
            // Read from stdin
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .map_err(|source| FnoxError::StdinReadFailed { source })?;
            Ok(input)
        }
    }

    fn parse_input(&self, input: &str) -> Result<HashMap<String, String>> {
        let source_name = self
            .input
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<stdin>".to_string());

        let format = match self.format {
            ImportFormat::Env => SecretFileFormat::Env,
            ImportFormat::Json => SecretFileFormat::Json,
            ImportFormat::Yaml => SecretFileFormat::Yaml,
            ImportFormat::Toml => SecretFileFormat::Toml,
        };
        format.parse(input, &source_name)
    }
}
