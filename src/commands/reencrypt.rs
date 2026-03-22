use crate::commands::Cli;
use crate::config::{Config, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secrets_batch;
use clap::Args;
use console;
use indexmap::IndexMap;
use regex::Regex;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

/// Re-encrypt secrets with current provider configuration
///
/// When you add or remove recipients from an encryption provider (e.g. age),
/// existing secrets remain encrypted with the old recipient set. This command
/// decrypts and re-encrypts all matching secrets with the current provider
/// configuration.
#[derive(Args)]
pub struct ReencryptCommand {
    /// Only re-encrypt these specific secret keys
    keys: Vec<String>,

    /// Skip confirmation prompt
    #[arg(short, long)]
    force: bool,

    /// Show what would be done without making changes
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Only re-encrypt secrets from this provider
    #[arg(short = 'p', long)]
    provider: Option<String>,

    /// Only re-encrypt matching secrets (regex pattern)
    #[arg(long)]
    filter: Option<String>,
}

impl ReencryptCommand {
    pub async fn run(&self, cli: &Cli, merged_config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Re-encrypting secrets for profile '{}'", profile);

        let providers = merged_config.get_providers(&profile);
        let all_secrets = merged_config.get_secrets(&profile)?;

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

        let keys_filter: std::collections::HashSet<_> = self.keys.iter().collect();

        // Resolve and cache encryption providers; track non-encryption providers
        // to avoid redundant resolution
        let mut provider_cache: HashMap<String, Box<dyn crate::providers::Provider>> =
            HashMap::new();
        let mut non_encryption_providers: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Collect secrets that use encryption providers
        let mut secrets_to_reencrypt: IndexMap<String, (String, SecretConfig)> = IndexMap::new();

        for (key, secret_config) in &all_secrets {
            let Some(provider_name) = secret_config.provider() else {
                continue;
            };

            // Apply --provider filter
            if let Some(ref p) = self.provider
                && provider_name != p
            {
                continue;
            }

            // Apply positional KEYS filter
            if !keys_filter.is_empty() && !keys_filter.contains(key) {
                continue;
            }

            // Apply --filter regex
            if let Some(ref regex) = filter_regex
                && !regex.is_match(key)
            {
                continue;
            }

            // Skip providers already known to lack Encryption capability
            if non_encryption_providers.contains(provider_name) {
                continue;
            }

            // Check if provider has Encryption capability (resolve once and cache)
            let Some(provider_config) = providers.get(provider_name) else {
                continue;
            };
            if !provider_cache.contains_key(provider_name) {
                let provider = crate::providers::get_provider_resolved(
                    &merged_config,
                    &profile,
                    provider_name,
                    provider_config,
                )
                .await?;
                if !provider
                    .capabilities()
                    .contains(&crate::providers::ProviderCapability::Encryption)
                {
                    non_encryption_providers.insert(provider_name.to_string());
                    continue;
                }
                provider_cache.insert(provider_name.to_string(), provider);
            }

            secrets_to_reencrypt.insert(
                key.clone(),
                (provider_name.to_string(), secret_config.clone()),
            );
        }

        // Warn about explicitly-requested keys that weren't found or eligible
        for key in &self.keys {
            if !secrets_to_reencrypt.contains_key(key) {
                tracing::warn!(
                    "Key '{}' was not found or is not eligible for re-encryption",
                    key
                );
            }
        }

        if secrets_to_reencrypt.is_empty() {
            println!("No secrets to re-encrypt");
            return Ok(());
        }

        // Dry-run mode
        if self.dry_run {
            let dry_run_label = console::style("[dry-run]").yellow().bold();
            let styled_profile = console::style(&profile).magenta();

            println!(
                "{dry_run_label} Would re-encrypt {} secrets in profile {styled_profile}:",
                secrets_to_reencrypt.len()
            );
            for (key, (provider_name, _)) in &secrets_to_reencrypt {
                println!(
                    "  {} ({})",
                    console::style(key).cyan(),
                    console::style(provider_name).green()
                );
            }
            return Ok(());
        }

        // Confirm unless forced
        if !self.force {
            println!(
                "\nReady to re-encrypt {} secrets in profile '{}':",
                secrets_to_reencrypt.len(),
                profile
            );
            for (key, (provider_name, _)) in secrets_to_reencrypt.iter().take(10) {
                println!("  {} ({})", key, provider_name);
            }
            if secrets_to_reencrypt.len() > 10 {
                println!("  ... and {} more", secrets_to_reencrypt.len() - 10);
            }

            println!("\nContinue? [y/N]");
            let mut response = String::new();
            io::stdin()
                .read_line(&mut response)
                .map_err(|e| FnoxError::StdinReadFailed { source: e })?;

            if !response.trim().to_lowercase().starts_with('y') {
                println!("Re-encryption cancelled");
                return Ok(());
            }
        }

        // Build a SecretConfig map for batch resolution (decrypt step).
        // Strip json_path so we get the full encrypted value, not the extracted field.
        let secrets_for_resolve: IndexMap<String, SecretConfig> = secrets_to_reencrypt
            .iter()
            .map(|(key, (_, sc))| {
                let mut resolve_config = sc.clone();
                resolve_config.json_path = None;
                (key.clone(), resolve_config)
            })
            .collect();

        let resolved =
            resolve_secrets_batch(&merged_config, &profile, &secrets_for_resolve).await?;

        // Re-encrypt each secret and group by source file
        let mut by_source: IndexMap<PathBuf, IndexMap<String, SecretConfig>> = IndexMap::new();
        let mut reencrypted_count = 0;
        let mut skipped_count = 0;

        for (key, plaintext) in &resolved {
            let Some(plaintext) = plaintext else {
                tracing::warn!("Skipping '{}': could not resolve value", key);
                skipped_count += 1;
                continue;
            };

            let (provider_name, secret_config) = &secrets_to_reencrypt[key];

            let provider = provider_cache.get(provider_name.as_str()).ok_or_else(|| {
                FnoxError::ProviderNotConfigured {
                    provider: provider_name.clone(),
                    profile: profile.to_string(),
                    config_path: None,
                    suggestion: None,
                }
            })?;

            match provider.encrypt(plaintext).await {
                Ok(encrypted) => {
                    let mut updated = secret_config.clone();
                    updated.set_value(Some(encrypted));

                    let source_path = secret_config
                        .source_path
                        .clone()
                        .unwrap_or_else(|| cli.config.clone());

                    by_source
                        .entry(source_path)
                        .or_default()
                        .insert(key.clone(), updated);
                    reencrypted_count += 1;
                }
                Err(e) => {
                    return Err(FnoxError::ReencryptEncryptionFailed {
                        key: key.clone(),
                        provider: provider_name.clone(),
                        details: e.to_string(),
                    });
                }
            }
        }

        // Save back to each source file
        for (source_path, secrets) in &by_source {
            Config::save_secrets_to_source(secrets, &profile, source_path)?;
        }

        println!("Re-encrypted {} secrets", reencrypted_count);
        if skipped_count > 0 {
            println!("Skipped {} secrets (could not resolve)", skipped_count);
        }

        Ok(())
    }
}
