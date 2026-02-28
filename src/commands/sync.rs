use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secrets_batch;
use clap::Args;
use console;
use indexmap::IndexMap;
use regex::Regex;
use std::io;

/// Sync secrets from remote providers to a local encryption provider
#[derive(Args)]
pub struct SyncCommand {
    /// Only sync these specific secret keys
    keys: Vec<String>,

    /// Skip confirmation prompt
    #[arg(short, long)]
    force: bool,

    /// Write to global config (~/.config/fnox/config.toml)
    #[arg(short = 'g', long)]
    global: bool,

    /// Show what would be done without making changes
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Target encryption provider (defaults to default_provider)
    #[arg(short = 'p', long)]
    provider: Option<String>,

    /// Only sync secrets from this source provider
    #[arg(short = 's', long)]
    source: Option<String>,

    /// Only sync matching secrets (regex pattern)
    #[arg(long)]
    filter: Option<String>,
}

impl SyncCommand {
    pub async fn run(&self, cli: &Cli, merged_config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Syncing secrets for profile '{}'", profile);

        // Determine target provider
        let target_provider_name = if let Some(ref p) = self.provider {
            p.clone()
        } else if let Some(dp) = merged_config.get_default_provider(&profile)? {
            dp
        } else {
            return Err(FnoxError::Config(
                "No target provider specified and no default_provider configured. Use -p <provider> to specify one.".to_string(),
            ));
        };

        // Verify target provider exists and has Encryption capability
        let providers = merged_config.get_providers(&profile);
        let provider_config = providers.get(&target_provider_name).ok_or_else(|| {
            FnoxError::ProviderNotConfigured {
                provider: target_provider_name.clone(),
                profile: profile.to_string(),
                config_path: None,
                suggestion: None,
            }
        })?;

        let target_provider = crate::providers::get_provider_resolved(
            &merged_config,
            &profile,
            &target_provider_name,
            provider_config,
        )
        .await?;
        let capabilities = target_provider.capabilities();
        if !capabilities.contains(&crate::providers::ProviderCapability::Encryption) {
            return Err(FnoxError::SyncTargetProviderUnsupported {
                provider: target_provider_name.clone(),
            });
        }

        // Get all secrets from config
        let all_secrets = merged_config.get_secrets(&profile)?;

        // Filter secrets to sync
        let filter_regex = if let Some(ref filter) = self.filter {
            Some(
                Regex::new(filter).map_err(|e| FnoxError::InvalidRegexFilter {
                    pattern: filter.clone(),
                    details: e.to_string(),
                })?,
            )
        } else {
            None
        };

        let mut secrets_to_sync = IndexMap::new();
        for (key, secret_config) in &all_secrets {
            // Must have a provider configured (skip env-var-only and default-only secrets)
            let Some(source_provider) = secret_config.provider() else {
                continue;
            };

            // Must not already use the target provider
            if source_provider == target_provider_name {
                continue;
            }

            // Apply --source filter
            if let Some(ref source) = self.source
                && source_provider != source {
                    continue;
                }

            // Apply positional KEYS filter
            if !self.keys.is_empty() && !self.keys.iter().any(|k| k == key) {
                continue;
            }

            // Apply --filter regex
            if let Some(ref regex) = filter_regex
                && !regex.is_match(key) {
                    continue;
                }

            secrets_to_sync.insert(key.clone(), secret_config.clone());
        }

        if secrets_to_sync.is_empty() {
            println!("No secrets to sync");
            return Ok(());
        }

        // Dry-run mode: show what would be done and exit
        if self.dry_run {
            let dry_run_label = console::style("[dry-run]").yellow().bold();
            let styled_profile = console::style(&profile).magenta();
            let styled_provider = console::style(&target_provider_name).green();
            let global_suffix = if self.global { " (global)" } else { "" };

            println!(
                "{dry_run_label} Would sync {} secrets in profile {styled_profile} to provider {styled_provider}{global_suffix}:",
                secrets_to_sync.len()
            );
            for (key, secret_config) in &secrets_to_sync {
                let source = secret_config.provider().unwrap_or("unknown");
                println!(
                    "  {} (from {})",
                    console::style(key).cyan(),
                    console::style(source).dim()
                );
            }
            return Ok(());
        }

        // Confirm unless forced
        if !self.force {
            println!(
                "\nReady to sync {} secrets to provider '{}':",
                secrets_to_sync.len(),
                target_provider_name
            );
            for (key, secret_config) in secrets_to_sync.iter().take(10) {
                let source = secret_config.provider().unwrap_or("unknown");
                println!("  {} (from {})", key, source);
            }
            if secrets_to_sync.len() > 10 {
                println!("  ... and {} more", secrets_to_sync.len() - 10);
            }

            println!("\nContinue? [y/N]");
            let mut response = String::new();
            io::stdin()
                .read_line(&mut response)
                .map_err(|e| FnoxError::StdinReadFailed { source: e })?;

            if !response.trim().to_lowercase().starts_with('y') {
                println!("Sync cancelled");
                return Ok(());
            }
        }

        // Resolve plaintext values from source providers
        let resolved = resolve_secrets_batch(&merged_config, &profile, &secrets_to_sync).await?;

        // Encrypt each value and build updated secret configs
        let mut synced_secrets = IndexMap::new();
        let mut synced_count = 0;
        let mut skipped_count = 0;

        // Determine target config file path
        let target_path = if self.global {
            let global_path = Config::global_config_path();
            if let Some(parent) = global_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| FnoxError::CreateDirFailed {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
            global_path
        } else {
            cli.config.clone()
        };

        // Load existing target config to preserve metadata
        let mut existing_config = if target_path.exists() {
            Some(Config::load(&target_path)?)
        } else {
            None
        };

        for (key, plaintext) in &resolved {
            let Some(plaintext) = plaintext else {
                tracing::warn!("Skipping '{}': could not resolve value", key);
                skipped_count += 1;
                continue;
            };

            // Start from existing config if key already exists, to preserve metadata
            let mut secret_config = existing_config
                .as_mut()
                .and_then(|c| c.get_secrets_mut(&profile).shift_remove(key))
                .unwrap_or_else(|| secrets_to_sync[key].clone());

            // Encrypt with target provider
            match target_provider.encrypt(plaintext).await {
                Ok(encrypted) => {
                    secret_config.set_provider(Some(target_provider_name.clone()));
                    secret_config.set_value(Some(encrypted));
                    synced_secrets.insert(key.clone(), secret_config);
                    synced_count += 1;
                }
                Err(e) => {
                    return Err(FnoxError::SyncEncryptionFailed {
                        key: key.clone(),
                        provider: target_provider_name.clone(),
                        details: e.to_string(),
                    });
                }
            }
        }

        if synced_secrets.is_empty() {
            println!("No secrets were synced (all skipped)");
            return Ok(());
        }

        // Save to config
        Config::save_secrets_to_source(&synced_secrets, &profile, &target_path)?;

        let global_suffix = if self.global { " (global)" } else { "" };
        println!(
            "Synced {} secrets to provider '{}'{}",
            synced_count, target_provider_name, global_suffix
        );
        if skipped_count > 0 {
            println!("Skipped {} secrets (could not resolve)", skipped_count);
        }

        Ok(())
    }
}
