use crate::commands::Cli;
use crate::config::{self, Config, SecretConfig, SyncConfig, local_override_filename};
use crate::error::{FnoxError, Result};
use crate::files::{self, FileConfig, FileEntry};
use crate::secret_resolver::resolve_secrets_batch;
use crate::settings::Settings;
use console;
use indexmap::IndexMap;
use regex::Regex;
use std::io;
use std::path::{Path, PathBuf};

/// Cache remote secrets locally, encrypted with a local provider
///
/// Fetches each secret whose provider differs from the target, encrypts the
/// value with the target encryption provider, and stores the ciphertext in the
/// secret's `sync` field. Later reads decrypt that copy instead of calling the
/// source provider. The original reference stays in place, so run sync again
/// after source values change.
///
/// The target is `--provider`, else `default_provider`, and must be an
/// encryption provider. The cache is written to the `-c` file (default:
/// `fnox.toml`), the global config with `--global`, or with `--local-file` a
/// personal `fnox.local.toml` to keep out of git. A full `--local-file` sync
/// also removes cache entries for secrets that no longer have a source.
///
/// The files of the active profiles (see `fnox files`) are cached the same way,
/// in the global config entry that declares them. KEYS and `--filter` match a
/// file by its path as written in the config, such as `~/.kube/config`.
#[derive(usage_rs::Args)]
#[usage(
    example(
        "fnox sync -p sync-age --local-file --dry-run",
        header = "Preview a local sync"
    ),
    example(
        "fnox sync -p sync-age --local-file",
        header = "Cache every remote secret in fnox.local.toml"
    ),
    example(
        "fnox sync -p sync-age --local-file DATABASE_URL",
        header = "Refresh one secret"
    ),
    after_long_help = "See also:\n- Sync: https://fnox.jdx.dev/guide/sync"
)]
pub struct SyncCommand {
    /// Sync only these keys
    keys: Vec<String>,

    /// Write without asking for confirmation
    #[usage(short, long)]
    force: bool,

    /// Write the cache to the global config file (`~/.config/fnox/config.toml`)
    #[usage(short = 'g', long)]
    global: bool,

    /// List the secrets that would be synced without changing anything
    #[usage(short = 'n', long)]
    dry_run: bool,

    /// Encryption provider to cache values with (default: `default_provider`)
    #[usage(short = 'p', long)]
    provider: Option<String>,

    /// Sync only secrets from this source provider
    #[usage(short = 's', long)]
    source: Option<String>,

    /// Sync only keys matching this regular expression
    #[usage(long)]
    filter: Option<String>,

    /// Write the cache to the local override file beside the config
    ///
    /// The file is `fnox.local.toml`, or `.fnox.local.toml` when that file exists
    /// or the config is `.fnox.toml`. Requires `-c` to be a bare `fnox.toml` or
    /// `.fnox.toml`.
    #[usage(long, conflicts = "--global")]
    local_file: bool,
}

impl SyncCommand {
    /// The file entries to cache: those stored by another provider than the
    /// target that pass the `--source`, KEYS and `--filter` options. Also the
    /// entries now stored by the target itself that still carry an old cache,
    /// which would otherwise be read in place of the target.
    fn select_files(
        &self,
        config: &Config,
        profile: &[String],
        target_provider: &str,
        filter: Option<&Regex>,
    ) -> Result<(Vec<FileEntry>, Vec<FileEntry>)> {
        let wanted_paths: Vec<_> = self
            .keys
            .iter()
            .filter_map(|key| files::normalize_path(key, None).ok())
            .collect();
        let (mut to_sync, mut stale) = (Vec::new(), Vec::new());
        for entry in config.get_files(profile)? {
            let Some(provider) = entry.config.provider.as_deref() else {
                continue;
            };
            let selected = self
                .source
                .as_deref()
                .is_none_or(|source| provider == source)
                && (self.keys.is_empty()
                    || self.keys.contains(&entry.key)
                    || wanted_paths.contains(&entry.path))
                && filter.is_none_or(|regex| regex.is_match(&entry.key));
            if !selected {
                continue;
            }
            if provider != target_provider {
                to_sync.push(entry);
            } else if entry.config.sync.is_some() {
                stale.push(entry);
            }
        }
        Ok((to_sync, stale))
    }

    pub async fn run(&self, cli: &Cli, merged_config: Config) -> Result<()> {
        let profile = Config::get_profiles(cli.profile.as_slice());
        let write_profile = Config::resolve_write_profile(&profile, cli.write_profile.as_deref())?;
        tracing::debug!("Syncing secrets for profile '{}'", write_profile);

        if self.local_file && !config::uses_config_discovery(&cli.config) {
            return Err(FnoxError::Config(format!(
                "--local-file requires --config to be the bare filename 'fnox.toml' or '.fnox.toml'; '{}' is an explicit path and would not load the adjacent local override file",
                cli.config.display()
            )));
        }

        let source_config = if self.local_file {
            let config = Config::load_smart_without_local_sync(&cli.config)?;
            config.validate_profiles(&profile, None)?;
            Some(config)
        } else {
            None
        };
        let resolution_config = source_config.as_ref().unwrap_or(&merged_config);

        let effective_config_path =
            if cli.config == std::path::Path::new(config::DEFAULT_CONFIG_FILENAME) {
                let current_dir = std::env::current_dir().map_err(|e| {
                    FnoxError::Config(format!("Failed to get current directory: {}", e))
                })?;
                config::find_local_config(&current_dir, std::slice::from_ref(&write_profile))
            } else {
                cli.config.clone()
            };

        let local_override_filename = self
            .local_file
            .then(|| {
                local_override_filename(&effective_config_path).ok_or_else(|| {
                    FnoxError::Config(format!(
                        "--local-file requires --config to be 'fnox.toml' or '.fnox.toml'; '{}' would not load the adjacent local override file",
                        effective_config_path.display()
                    ))
                })
            })
            .transpose()?;

        // Determine target provider
        let target_provider_name = if let Some(ref p) = self.provider {
            p.clone()
        } else if let Some(dp) = resolution_config.get_default_provider(&profile)? {
            dp
        } else {
            return Err(FnoxError::Config(
                "No target provider specified and no default_provider configured. Use -p <provider> to specify one.".to_string(),
            ));
        };

        // Verify target provider exists and has Encryption capability
        let providers = resolution_config.get_providers(&profile)?;
        let provider_config = providers.get(&target_provider_name).ok_or_else(|| {
            FnoxError::ProviderNotConfigured {
                provider: target_provider_name.clone(),
                profile: Config::display_profiles(&profile),
                config_path: None,
                suggestion: None,
            }
        })?;

        let target_provider = crate::providers::get_provider_resolved(
            resolution_config,
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
        let all_secrets = resolution_config.get_secrets(&profile)?;

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

        let keys_filter: std::collections::HashSet<_> = self.keys.iter().collect();
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
                && source_provider != source
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

            secrets_to_sync.insert(key.clone(), secret_config.clone());
        }

        // File entries are cached in the config that declares them, whichever
        // destination the secrets are written to
        let (files_to_sync, stale_files) = self.select_files(
            resolution_config,
            &profile,
            &target_provider_name,
            filter_regex.as_ref(),
        )?;
        // Files are cached with the global config's providers, so fail now
        // rather than after the secrets are fetched
        let file_target = if files_to_sync.is_empty() {
            None
        } else {
            Some(files::sync_target(&profile, &target_provider_name).await?)
        };

        // Determine target config file path
        let (target_path, ensure_parent_dir, local_cache_paths) = if self.local_file {
            let config_dir = effective_config_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let standard_path = config_dir.join("fnox.local.toml");
            let hidden_path = config_dir.join(".fnox.local.toml");
            let paired_path = config_dir
                .join(local_override_filename.expect("validated local override filename"));
            let target_path = if hidden_path.exists() {
                hidden_path.clone()
            } else {
                paired_path
            };
            let local_cache_paths = [standard_path, hidden_path]
                .into_iter()
                .filter(|path| path.exists())
                .collect();
            (target_path, true, local_cache_paths)
        } else if self.global {
            (Config::global_config_path(), true, Vec::new())
        } else {
            (cli.config.clone(), false, Vec::new())
        };

        let is_full_local_sync = self.local_file
            && self.source.is_none()
            && self.filter.is_none()
            && self.keys.is_empty();
        let mut cache_profiles = resolution_config.resolve_profiles(&profile)?;
        let has_non_default = cache_profiles.iter().any(|profile| profile != "default");
        if (!has_non_default || !Settings::get().no_defaults)
            && !cache_profiles.iter().any(|profile| profile == "default")
        {
            cache_profiles.insert(0, "default".to_string());
        }
        if !cache_profiles.contains(&write_profile) {
            cache_profiles.push(write_profile.clone());
        }
        let mut stale_local_entries = Vec::new();
        // Personal secrets whose source no longer needs syncing (for example it
        // now uses the target provider) keep their entry but lose the old cache.
        let mut unsynced_local_entries = Vec::new();
        if is_full_local_sync {
            for path in &local_cache_paths {
                let local_config = Config::load(path)?;
                for profile in &cache_profiles {
                    let profile_secrets =
                        resolution_config.get_secrets(std::slice::from_ref(profile))?;
                    let cached_secrets = if profile == "default" {
                        Some(&local_config.secrets)
                    } else {
                        local_config
                            .profiles
                            .get(profile.as_str())
                            .map(|profile| &profile.secrets)
                    };
                    let unsynced = cached_secrets
                        .into_iter()
                        .flat_map(|secrets| secrets.iter())
                        .filter(|(key, secret)| {
                            // Another profile may still source this key from a
                            // remote provider, so check this profile's own source.
                            let has_profile_source =
                                profile_secrets.get(*key).is_some_and(|secret| {
                                    secret.provider().is_some_and(|source_provider| {
                                        source_provider != target_provider_name
                                    })
                                });
                            secret.sync.as_ref().is_some_and(|sync| sync.local_source)
                                && !has_profile_source
                        })
                        .map(|(key, secret)| {
                            let mut secret = secret.clone();
                            secret.sync = None;
                            (key.clone(), secret)
                        })
                        .collect::<IndexMap<_, _>>();
                    if !unsynced.is_empty() {
                        unsynced_local_entries.push((path.clone(), profile.clone(), unsynced));
                    }
                    let stale = cached_secrets
                        .into_iter()
                        .flat_map(|secrets| secrets.iter())
                        .filter(|(key, secret)| {
                            let has_profile_source =
                                profile_secrets.get(*key).is_some_and(|secret| {
                                    secret.provider().is_some_and(|source_provider| {
                                        source_provider != target_provider_name
                                    })
                                });
                            // A `local_source` entry is the personal secret's own
                            // definition, so it is never a removable cache copy.
                            secret.sync.as_ref().is_some_and(|sync| !sync.local_source)
                                && !secrets_to_sync.contains_key(*key)
                                && !has_profile_source
                        })
                        .map(|(key, _)| key.clone())
                        .collect::<Vec<_>>();
                    if !stale.is_empty() {
                        stale_local_entries.push((path.clone(), profile.clone(), stale));
                    }
                }
            }
        }
        let stale_local_secrets = stale_local_entries
            .iter()
            .flat_map(|(_, _, secrets)| secrets)
            .fold(Vec::new(), |mut names, name| {
                if !names.contains(name) {
                    names.push(name.clone());
                }
                names
            });
        let unsynced_local_secrets = unsynced_local_entries
            .iter()
            .flat_map(|(_, _, secrets)| secrets.keys())
            .fold(Vec::new(), |mut names, name| {
                if !names.contains(name) {
                    names.push(name.clone());
                }
                names
            });
        let unsynced_label = |key: &str| {
            if secrets_to_sync.contains_key(key) {
                "clear obsolete local cache unless refreshed above"
            } else {
                "clear obsolete local cache"
            }
        };
        let stale_local_entry_count = stale_local_entries
            .iter()
            .map(|(_, _, secrets)| secrets.len())
            .sum::<usize>();

        if secrets_to_sync.is_empty()
            && files_to_sync.is_empty()
            && stale_files.is_empty()
            && stale_local_secrets.is_empty()
            && unsynced_local_entries.is_empty()
        {
            println!("No secrets to sync");
            return Ok(());
        }

        let destination_suffix = if self.local_file {
            " (local-file)"
        } else if self.global {
            " (global)"
        } else {
            ""
        };

        // Dry-run mode: show what would be done and exit
        if self.dry_run {
            let dry_run_label = console::style("[dry-run]").yellow().bold();
            let styled_profile = console::style(&write_profile).magenta();
            let styled_provider = console::style(&target_provider_name).green();

            println!(
                "{dry_run_label} Would sync {} secrets in profile {styled_profile} to provider {styled_provider}{destination_suffix}:",
                secrets_to_sync.len() + files_to_sync.len()
            );
            for (key, secret_config) in &secrets_to_sync {
                let source = secret_config.provider().unwrap_or("unknown");
                println!(
                    "  {} (from {})",
                    console::style(key).cyan(),
                    console::style(source).dim()
                );
            }
            for entry in &files_to_sync {
                let source = entry.config.provider.as_deref().unwrap_or("unknown");
                println!(
                    "  {} (file, from {})",
                    console::style(&entry.key).cyan(),
                    console::style(source).dim()
                );
            }
            for entry in &stale_files {
                println!(
                    "  {} (file, remove stale cache)",
                    console::style(&entry.key).cyan()
                );
            }
            for key in &stale_local_secrets {
                println!(
                    "  {} (remove stale local cache)",
                    console::style(key).cyan()
                );
            }
            for key in &unsynced_local_secrets {
                println!("  {} ({})", console::style(key).cyan(), unsynced_label(key));
            }
            return Ok(());
        }

        // Confirm unless forced
        if !self.force {
            println!(
                "\nReady to sync {} secrets to provider '{}':",
                secrets_to_sync.len() + files_to_sync.len(),
                target_provider_name
            );
            for (key, secret_config) in secrets_to_sync.iter().take(10) {
                let source = secret_config.provider().unwrap_or("unknown");
                println!("  {} (from {})", key, source);
            }
            if secrets_to_sync.len() > 10 {
                println!("  ... and {} more", secrets_to_sync.len() - 10);
            }
            for entry in &files_to_sync {
                let source = entry.config.provider.as_deref().unwrap_or("unknown");
                println!("  {} (file, from {})", entry.key, source);
            }
            for entry in &stale_files {
                println!("  {} (file, remove stale cache)", entry.key);
            }
            for key in &stale_local_secrets {
                println!("  {} (remove stale local cache)", key);
            }
            for key in &unsynced_local_secrets {
                println!("  {} ({})", key, unsynced_label(key));
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

        // Resolve raw values from the original provider:
        // - Cached sync values would prevent picking up changes after the first sync.
        // - Post-processed values (e.g. from json_path) would cause future reads to fail.
        let secrets_for_resolve: IndexMap<String, SecretConfig> = secrets_to_sync
            .iter()
            .map(|(key, sc)| (key.clone(), sc.for_raw_resolve()))
            .collect();

        let resolved = if secrets_for_resolve.is_empty() {
            IndexMap::new()
        } else {
            resolve_secrets_batch(resolution_config, &profile, &secrets_for_resolve).await?
        };

        // Encrypt each value and build updated secret configs
        let mut synced_secrets = IndexMap::new();
        let mut synced_count = 0;
        let mut skipped_count = 0;

        if ensure_parent_dir
            && let Some(parent) = target_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| FnoxError::CreateDirFailed {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let plaintext_secrets: Vec<(String, String)> = resolved
            .iter()
            .filter_map(|(key, plaintext)| {
                plaintext
                    .as_ref()
                    .map(|plaintext| (key.clone(), plaintext.clone()))
            })
            .collect();
        let mut encrypted_secrets = target_provider
            .encrypt_secrets_batch(&plaintext_secrets)
            .await;

        for (key, plaintext) in &resolved {
            if plaintext.is_none() {
                tracing::warn!("Skipping '{}': could not resolve value", key);
                skipped_count += 1;
                continue;
            }

            let mut secret_config = secrets_to_sync[key].clone();

            // Encrypt with target provider
            match encrypted_secrets.remove(key).unwrap_or_else(|| {
                Err(FnoxError::Provider(format!(
                    "provider did not return an encrypted value for '{key}'"
                )))
            }) {
                Ok(encrypted) => {
                    secret_config.sync = Some(SyncConfig {
                        provider: target_provider_name.clone(),
                        value: encrypted,
                        local_source: is_local_source(&secret_config, &target_path, &write_profile),
                    });
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

        // Resolve and encrypt every file before writing anything. Encrypting
        // them as one batch lets the provider set up once for all of them.
        let mut file_plaintexts = Vec::with_capacity(files_to_sync.len());
        for entry in &files_to_sync {
            let plaintext = files::resolve_file_source(&profile, entry).await?;
            file_plaintexts.push((entry.key.clone(), plaintext));
        }
        let mut encrypted_files = match &file_target {
            Some(target) => target.encrypt_secrets_batch(&file_plaintexts).await,
            None => Default::default(),
        };
        let mut synced_files = Vec::with_capacity(files_to_sync.len());
        for entry in &files_to_sync {
            let encrypted = encrypted_files
                .remove(&entry.key)
                .unwrap_or_else(|| {
                    Err(FnoxError::Provider(format!(
                        "provider did not return an encrypted value for '{}'",
                        entry.key
                    )))
                })
                .map_err(|e| FnoxError::SyncEncryptionFailed {
                    key: entry.key.clone(),
                    provider: target_provider_name.clone(),
                    details: e.to_string(),
                })?;
            let mut file: FileConfig = entry.config.clone();
            file.sync = Some(SyncConfig {
                provider: target_provider_name.clone(),
                value: encrypted,
                local_source: false,
            });
            synced_files.push((entry, file));
        }

        if synced_secrets.is_empty()
            && synced_files.is_empty()
            && stale_files.is_empty()
            && stale_local_secrets.is_empty()
            && unsynced_local_entries.is_empty()
        {
            println!("No secrets were synced (all skipped)");
            return Ok(());
        }

        // Save to config
        let target_removals = stale_local_entries
            .iter()
            .find(|(path, profile, _)| path == &target_path && profile == &write_profile)
            .map(|(_, _, secrets)| secrets.as_slice())
            .unwrap_or_default();
        if !synced_secrets.is_empty() || !target_removals.is_empty() {
            Config::update_secrets_in_source(
                &synced_secrets,
                target_removals,
                &write_profile,
                &target_path,
            )?;
        }
        let no_secrets = IndexMap::new();
        for (path, profile, removals) in stale_local_entries
            .iter()
            .filter(|(path, profile, _)| path != &target_path || profile != &write_profile)
        {
            Config::update_secrets_in_source(&no_secrets, removals, profile, path)?;
        }
        for (path, profile, unsynced) in &unsynced_local_entries {
            // Entries this sync wrote carry a fresh cache; keep it.
            let mut unsynced = unsynced.clone();
            if path == &target_path && profile == &write_profile {
                unsynced.retain(|key, _| !synced_secrets.contains_key(key));
            }
            if !unsynced.is_empty() {
                Config::update_secrets_in_source(&unsynced, &[], profile, path)?;
            }
        }

        for (entry, file) in &synced_files {
            let declared_in = entry
                .config
                .source_path
                .clone()
                .unwrap_or_else(Config::global_config_path);
            files::save_entry(&declared_in, &entry.profile, &entry.key, file)?;
            synced_count += 1;
        }
        for entry in &stale_files {
            let declared_in = entry
                .config
                .source_path
                .clone()
                .unwrap_or_else(Config::global_config_path);
            let mut file = entry.config.clone();
            file.sync = None;
            files::save_entry(&declared_in, &entry.profile, &entry.key, &file)?;
        }

        if synced_count > 0 {
            println!(
                "Synced {} secrets to provider '{}'{}",
                synced_count, target_provider_name, destination_suffix
            );
        }
        if !stale_files.is_empty() {
            println!("Removed {} stale file caches", stale_files.len());
        }
        if !stale_local_secrets.is_empty() {
            println!(
                "Removed {} stale entries from the local cache",
                stale_local_entry_count
            );
        }
        if skipped_count > 0 {
            println!("Skipped {} secrets (could not resolve)", skipped_count);
        }

        Ok(())
    }
}

/// Whether the secret's source entry lives in the file and profile table that
/// `--local-file` is about to write, so the cached copy replaces the personal
/// original instead of shadowing an inherited secret.
fn is_local_source(secret: &SecretConfig, target_path: &Path, write_profile: &str) -> bool {
    let Some(source_path) = secret.source_path.as_deref() else {
        return false;
    };
    let same_table = if secret.source_is_profile {
        secret.source_profile.as_deref() == Some(write_profile)
    } else {
        write_profile == "default"
    };
    let same_file = match (source_path.canonicalize(), target_path.canonicalize()) {
        (Ok(source), Ok(target)) => source == target,
        _ => source_path == target_path,
    };
    same_table
        && same_file
        && matches!(
            source_path.file_name().and_then(|name| name.to_str()),
            Some("fnox.local.toml" | ".fnox.local.toml")
        )
}
