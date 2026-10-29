use crate::commands::Cli;
use crate::config::{Config, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secrets_batch;
use console;
use indexmap::IndexMap;
use regex::Regex;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

/// Re-encrypt stored secrets with the current provider settings
///
/// Decrypts each matching secret stored with an encryption provider, such as age
/// or a KMS, encrypts it again with that provider's current configuration, and
/// writes the new ciphertext to the file that defines it. Run it after changing
/// a provider's recipients or key, with an identity that can still decrypt the
/// existing values.
///
/// The files of the active profiles (see `fnox files`) are re-encrypted too,
/// unless you name secrets with KEYS.
///
/// fnox asks for confirmation unless you pass `--force`. Only the active
/// profile's secrets are processed, so repeat with `-P` for other profiles.
/// `fnox sync` caches on re-encrypted secrets are cleared; run `fnox sync` again
/// to rebuild them.
#[derive(usage_rs::Args)]
#[usage(
    example(
        "fnox reencrypt -p age --dry-run",
        header = "Preview which secrets change"
    ),
    example("fnox reencrypt -p age", header = "Re-encrypt every age secret"),
    example(
        "fnox -P staging reencrypt -p age --force",
        header = "Re-encrypt another profile without a prompt"
    ),
    after_long_help = "See also:\n- Teams: https://fnox.jdx.dev/guide/teams\n- Age: https://fnox.jdx.dev/providers/age"
)]
pub struct ReencryptCommand {
    /// Re-encrypt only these secrets; without them, files are re-encrypted too
    keys: Vec<String>,

    /// Write without asking for confirmation
    #[usage(short, long)]
    force: bool,

    /// List the secrets that would be re-encrypted without changing anything
    #[usage(short = 'n', long)]
    dry_run: bool,

    /// Re-encrypt only secrets stored with this provider
    #[usage(short = 'p', long)]
    provider: Option<String>,

    /// Re-encrypt only keys matching this regular expression
    #[usage(long)]
    filter: Option<String>,
}

/// What re-encrypting the files did
#[derive(Debug, Default)]
struct FilesOutcome {
    /// How many files were selected
    selected: usize,
    /// The user answered no, which cancels the whole command
    cancelled: bool,
}

impl FilesOutcome {
    fn selected(selected: usize) -> Self {
        Self {
            selected,
            cancelled: false,
        }
    }

    fn cancelled(selected: usize) -> Self {
        Self {
            selected,
            cancelled: true,
        }
    }
}

impl ReencryptCommand {
    pub async fn run(&self, cli: &Cli, merged_config: Config) -> Result<()> {
        // KEYS name secrets, so they leave the files out
        let files = if self.keys.is_empty() {
            self.reencrypt_files(cli, &merged_config).await?
        } else {
            FilesOutcome::default()
        };
        if files.cancelled {
            return Ok(());
        }
        self.reencrypt_secrets(cli, merged_config, files.selected > 0)
            .await
    }

    /// Re-encrypt the files of the active profiles
    async fn reencrypt_files(&self, cli: &Cli, config: &Config) -> Result<FilesOutcome> {
        let profile = Config::get_profiles(cli.profile.as_slice());
        let entries = config.get_files(&profile)?;
        if entries.is_empty() {
            return Ok(FilesOutcome::default());
        }
        // Files are encrypted with the providers of the global config only
        let trusted = Config::load_global_only()?;
        let providers = trusted.get_providers(&profile)?;
        let default_provider = trusted.get_default_provider(&profile)?;
        let filter_regex = self
            .filter
            .as_ref()
            .map(|filter| {
                Regex::new(filter).map_err(|e| FnoxError::InvalidRegexFilter {
                    pattern: filter.clone(),
                    details: e.to_string(),
                })
            })
            .transpose()?;

        let mut selected = Vec::new();
        for entry in entries {
            let Some(provider_name) = entry.config.provider.clone().or(default_provider.clone())
            else {
                continue;
            };
            if self.provider.as_ref().is_some_and(|p| *p != provider_name)
                || filter_regex
                    .as_ref()
                    .is_some_and(|r| !r.is_match(&entry.key))
                || (entry.config.value.is_none() && entry.config.source.is_none())
            {
                continue;
            }
            let Some(provider_config) = providers.get(provider_name.as_str()) else {
                tracing::warn!(
                    "Skipping '{}': provider '{provider_name}' not found in current config",
                    entry.key
                );
                continue;
            };
            let provider = crate::providers::get_provider_resolved(
                &trusted,
                &profile,
                &provider_name,
                provider_config,
            )
            .await?;
            if provider
                .capabilities()
                .contains(&crate::providers::ProviderCapability::Encryption)
            {
                selected.push((entry, provider_name, provider));
            }
        }
        if selected.is_empty() {
            return Ok(FilesOutcome::default());
        }

        let profile_display = Config::display_profiles(&profile);
        if self.dry_run {
            let label = console::style("[dry-run]").yellow().bold();
            println!(
                "{label} Would re-encrypt {} files in profile {}:",
                selected.len(),
                console::style(&profile_display).magenta()
            );
            for (entry, provider_name, _) in &selected {
                println!(
                    "  {} ({})",
                    console::style(&entry.key).cyan(),
                    console::style(provider_name).green()
                );
            }
            return Ok(FilesOutcome::selected(selected.len()));
        }
        if !self.force {
            println!(
                "\nReady to re-encrypt {} files in profile '{}':",
                selected.len(),
                profile_display
            );
            for (entry, provider_name, _) in &selected {
                println!("  {} ({})", entry.key, provider_name);
            }
            println!("\nContinue? [y/N]");
            let mut response = String::new();
            io::stdin()
                .read_line(&mut response)
                .map_err(|e| FnoxError::StdinReadFailed { source: e })?;
            if !response.trim().to_lowercase().starts_with('y') {
                println!("Re-encryption cancelled");
                return Ok(FilesOutcome::cancelled(selected.len()));
            }
        }

        // Encrypt every file before writing any of them
        let declared = config.declared_files();
        let mut updated = Vec::with_capacity(selected.len());
        for (entry, provider_name, provider) in &selected {
            let plaintext = crate::files::resolve_file(&profile, entry)
                .await
                .map_err(|e| FnoxError::ReencryptDecryptFailed {
                    key: entry.key.clone(),
                    details: e.to_string(),
                })?;
            let encrypted = provider.encrypt(&plaintext).await.map_err(|e| {
                FnoxError::ReencryptEncryptionFailed {
                    key: entry.key.clone(),
                    provider: provider_name.clone(),
                    details: e.to_string(),
                }
            })?;
            // Refuse a linked source that the write would destroy before writing any
            let others = declared
                .iter()
                .filter(|e| !(e.path == entry.path && e.profile == entry.profile));
            let source_file = crate::files::source_target(&entry.config, others)?;
            updated.push((entry, encrypted, source_file));
        }
        for (entry, encrypted, source_file) in &updated {
            let declared_in = entry
                .config
                .source_path
                .clone()
                .unwrap_or_else(Config::global_config_path);
            let mut file = entry.config.clone();
            match source_file {
                Some(source_file) => {
                    crate::files::write_file(source_file, encrypted)?;
                }
                None => file.value = Some(encrypted.clone()),
            }
            crate::files::save_entry(&declared_in, &entry.profile, &entry.key, &file)?;
        }
        println!("Re-encrypted {} files", updated.len());
        Ok(FilesOutcome::selected(selected.len()))
    }

    async fn reencrypt_secrets(
        &self,
        cli: &Cli,
        merged_config: Config,
        has_files: bool,
    ) -> Result<()> {
        let profile = Config::get_profiles(cli.profile.as_slice());
        tracing::debug!(
            "Re-encrypting secrets for profiles '{}'",
            Config::display_profiles(&profile)
        );

        let profile_display = Config::display_profiles(&profile);

        let providers = merged_config.get_providers(&profile)?;
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

        let default_provider = merged_config.get_default_provider(&profile)?;

        for (key, secret_config) in &all_secrets {
            let provider_name = if let Some(p) = secret_config.provider() {
                p.to_string()
            } else if let Some(ref dp) = default_provider {
                dp.clone()
            } else {
                continue;
            };

            // Apply --provider filter
            if let Some(ref p) = self.provider
                && provider_name != *p
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
            if non_encryption_providers.contains(&provider_name) {
                continue;
            }

            // Check if provider has Encryption capability (resolve once and cache)
            let Some(provider_config) = providers.get(provider_name.as_str()) else {
                tracing::warn!(
                    "Skipping '{key}': provider '{provider_name}' not found in current config"
                );
                continue;
            };
            if !provider_cache.contains_key(&provider_name) {
                let provider = crate::providers::get_provider_resolved(
                    &merged_config,
                    &profile,
                    &provider_name,
                    provider_config,
                )
                .await?;
                if !provider
                    .capabilities()
                    .contains(&crate::providers::ProviderCapability::Encryption)
                {
                    non_encryption_providers.insert(provider_name.clone());
                    continue;
                }
                provider_cache.insert(provider_name.clone(), provider);
            }

            // Skip secrets with no stored ciphertext — nothing to re-encrypt
            if secret_config.value().is_none() {
                tracing::debug!("Skipping '{key}': no encrypted value stored");
                continue;
            }

            secrets_to_reencrypt.insert(key.clone(), (provider_name, secret_config.clone()));
        }

        // Error if explicitly-requested keys weren't found or eligible
        for key in &self.keys {
            if !secrets_to_reencrypt.contains_key(key) {
                return Err(FnoxError::SecretNotFound {
                    key: key.clone(),
                    profile: profile_display.clone(),
                    config_path: None,
                    suggestion: Some(format!(
                        "The key was not found, does not use an encryption provider, or was excluded by filters{}{}",
                        self.provider
                            .as_ref()
                            .map(|p| format!(" (--provider {})", p))
                            .unwrap_or_default(),
                        self.filter
                            .as_ref()
                            .map(|f| format!(" (--filter {})", f))
                            .unwrap_or_default(),
                    )),
                });
            }
        }

        if secrets_to_reencrypt.is_empty() {
            if !has_files {
                println!("No secrets to re-encrypt");
            }
            return Ok(());
        }

        // Dry-run mode
        if self.dry_run {
            let dry_run_label = console::style("[dry-run]").yellow().bold();
            let styled_profile = console::style(&profile_display).magenta();

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
                profile_display
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

        // Resolve raw values from the original provider:
        // - Cached sync values would reencrypt stale data instead of the latest.
        // - Post-processed values (e.g. from json_path) would cause future reads to fail.
        let secrets_for_resolve: IndexMap<String, SecretConfig> = secrets_to_reencrypt
            .iter()
            .map(|(key, (_, sc))| (key.clone(), sc.for_raw_resolve()))
            .collect();

        let resolved = resolve_secrets_batch(&merged_config, &profile, &secrets_for_resolve).await;

        // Scrub decrypted plaintext from the process environment regardless of
        // success/failure. resolve_secrets_batch calls set_var for each resolved
        // secret, which leaks plaintext here (visible via /proc and inherited by
        // child processes).
        for key in secrets_to_reencrypt.keys() {
            // SAFETY: reencrypt is single-threaded at this point; no other threads
            // are reading the environment concurrently.
            unsafe {
                std::env::remove_var(key);
            }
        }

        let resolved = resolved?;

        // Verify all secrets were resolved (catch silent drops from resolve_secrets_batch)
        for key in secrets_to_reencrypt.keys() {
            if !resolved.contains_key(key) {
                return Err(FnoxError::ReencryptDecryptFailed {
                    key: key.clone(),
                    details: "secret was not returned by the resolver".to_string(),
                });
            }
        }

        // Batch by effective provider so hardware-backed providers can share
        // one encryption operation across all selected secrets.
        let mut by_provider: IndexMap<&str, Vec<(String, String)>> = IndexMap::new();
        for (key, plaintext) in resolved {
            let Some(plaintext) = plaintext else {
                return Err(FnoxError::ReencryptDecryptFailed {
                    key,
                    details: "resolver returned no value for this secret".to_string(),
                });
            };

            let (provider_name, _) = &secrets_to_reencrypt[&key];
            by_provider
                .entry(provider_name.as_str())
                .or_default()
                .push((key, plaintext));
        }

        // Collect every encrypted value before saving any source file.
        let mut by_source: IndexMap<(PathBuf, String), IndexMap<String, SecretConfig>> =
            IndexMap::new();
        let mut reencrypted_count = 0;

        for (provider_name, plaintext_secrets) in by_provider {
            let provider = provider_cache.get(provider_name).ok_or_else(|| {
                FnoxError::ProviderNotConfigured {
                    provider: provider_name.to_string(),
                    profile: profile_display.clone(),
                    config_path: None,
                    suggestion: None,
                }
            })?;
            let mut encrypted_secrets = provider.encrypt_secrets_batch(&plaintext_secrets).await;

            for (key, _) in plaintext_secrets {
                let (_, secret_config) = &secrets_to_reencrypt[&key];
                match encrypted_secrets.remove(&key).unwrap_or_else(|| {
                    Err(FnoxError::Provider(format!(
                        "provider did not return an encrypted value for '{key}'"
                    )))
                }) {
                    Ok(encrypted) => {
                        let mut updated = secret_config.clone();
                        updated.set_value(Some(encrypted));
                        updated.sync = None; // Clear stale sync cache

                        let source_path =
                        secret_config.source_path.clone().ok_or_else(|| {
                            FnoxError::Config(format!(
                                "Secret '{}' has no known source file; cannot write back re-encrypted value",
                                key
                            ))
                        })?;

                        // Use source_profile to determine the correct TOML section.
                        // Secrets loaded from root [secrets] must be saved back there,
                        // not to [profiles.X.secrets].
                        let save_profile = secret_config
                            .source_profile
                            .clone()
                            .unwrap_or_else(|| "default".to_string());

                        by_source
                            .entry((source_path, save_profile))
                            .or_default()
                            .insert(key.clone(), updated);
                        reencrypted_count += 1;
                    }
                    Err(e) => {
                        return Err(FnoxError::ReencryptEncryptionFailed {
                            key: key.clone(),
                            provider: provider_name.to_string(),
                            details: e.to_string(),
                        });
                    }
                }
            }
        }

        // Save back to each source file under the correct TOML section
        for ((source_path, save_profile), secrets) in &by_source {
            Config::save_secrets_to_source(secrets, save_profile, source_path)?;
        }

        println!("Re-encrypted {} secrets", reencrypted_count);

        Ok(())
    }
}
