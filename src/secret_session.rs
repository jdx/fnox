//! A long-running command's view of its secrets, shared by the MCP server and
//! the credential proxy.
//!
//! A session resolves secrets on demand and caches the values in memory. It can
//! also store a new value the way `fnox set` would and load it back from the
//! config on disk, so a value set during the session, here or with `fnox set`,
//! is used without a restart.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use indexmap::IndexMap;
use tokio::sync::{OnceCell, RwLock};

use crate::commands::set::{SetCommand, local_target_path, storage_provider, stores_securely};
use crate::config::{self, Config, SecretConfig};
use crate::daemon::{Purpose, ResolveContext};
use crate::error::{FnoxError, Result};
use crate::generate::GenerateKind;

/// Where a new value for a secret would be stored
pub enum StorageProvider {
    /// A provider that encrypts the value or stores it remotely
    Secure(String),
    /// Why storing would leave the value in plain text, or can't be done
    Refused(String),
}

pub struct SecretSession {
    /// The config the session started with
    config: Config,
    /// `--config` value, for reloading the config and finding the file a new
    /// value is written to
    config_path: PathBuf,
    profile: Vec<String>,
    /// `--write-profile` value
    write_profile: Option<String>,
    context: ResolveContext,
    purpose: Purpose,
    /// Replaced, not mutated, when a secret is added during the session
    secrets: std::sync::RwLock<Arc<IndexMap<String, SecretConfig>>>,
    /// Resolved values. `None` means "resolved but absent".
    cache: RwLock<HashMap<String, Option<String>>>,
    /// Set once the first batch has been resolved (separate from the cache,
    /// since every secret in it may be absent)
    batch: OnceCell<()>,
    /// Held while a value is rechecked and stored, so two stores can't both
    /// pass their checks and overwrite each other
    store_lock: tokio::sync::Mutex<()>,
}

impl SecretSession {
    pub fn new(
        config: Config,
        profile: Vec<String>,
        context: ResolveContext,
        purpose: Purpose,
        secrets: IndexMap<String, SecretConfig>,
    ) -> Self {
        Self {
            config,
            config_path: PathBuf::from(config::DEFAULT_CONFIG_FILENAME),
            profile,
            write_profile: None,
            context,
            purpose,
            secrets: std::sync::RwLock::new(Arc::new(secrets)),
            cache: RwLock::new(HashMap::new()),
            batch: OnceCell::new(),
            store_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Set the `--config` and `--write-profile` values that decide where a new
    /// value is stored, as `fnox set` would
    pub fn with_write_target(
        mut self,
        config_path: PathBuf,
        write_profile: Option<String>,
    ) -> Self {
        self.config_path = config_path;
        self.write_profile = write_profile;
        self
    }

    pub fn profile(&self) -> &[String] {
        &self.profile
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn write_profile_flag(&self) -> Option<&str> {
        self.write_profile.as_deref()
    }

    /// The secrets this session can reach
    pub fn secrets(&self) -> Arc<IndexMap<String, SecretConfig>> {
        self.secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The cached value of `name`: `None` if it hasn't been resolved,
    /// `Some(None)` if it resolved to nothing
    pub async fn cached(&self, name: &str) -> Option<Option<String>> {
        self.cache.read().await.get(name).cloned()
    }

    /// The cached values whose names `include` selects, skipping absent ones.
    /// Only the selected values are copied.
    pub async fn cached_values_where(
        &self,
        include: impl Fn(&str) -> bool,
    ) -> Vec<(String, String)> {
        self.cache
            .read()
            .await
            .iter()
            .filter(|(key, _)| include(key))
            .filter_map(|(key, value)| value.as_ref().map(|value| (key.clone(), value.clone())))
            .collect()
    }

    /// Drop the cached value of `name`
    pub async fn forget(&self, name: &str) {
        self.cache.write().await.remove(name);
    }

    /// Make a secret and its value available to the session
    pub async fn add(&self, name: &str, secret: SecretConfig, value: String) {
        // Cache the value before publishing the secret: a first batch that
        // starts in between skips cached names, so it never resolves this one
        // against the starting config
        self.cache
            .write()
            .await
            .insert(name.to_string(), Some(value));
        let mut secrets = self.secrets.write().unwrap_or_else(|e| e.into_inner());
        let mut updated = (**secrets).clone();
        updated.insert(name.to_string(), secret);
        *secrets = Arc::new(updated);
    }

    /// Resolve the secrets `include` selects, once per session, in one batch
    /// (one YubiKey touch or SSO prompt). Later calls do nothing.
    pub async fn resolve_batch_once(&self, include: impl Fn(&SecretConfig) -> bool) -> Result<()> {
        self.batch
            .get_or_try_init(|| async {
                // Skip any already cached: a secret stored during the session
                // may name a provider the starting config predates
                let batch: IndexMap<String, SecretConfig> = {
                    let cached = self.cache.read().await;
                    self.secrets()
                        .iter()
                        .filter(|(k, sc)| include(sc) && !cached.contains_key(*k))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                };
                self.resolve_now(&batch).await?;
                Ok::<(), FnoxError>(())
            })
            .await?;
        Ok(())
    }

    /// Resolve `secrets` now with the starting config and cache the results,
    /// keeping any value stored while the batch ran
    pub async fn resolve_now(
        &self,
        secrets: &IndexMap<String, SecretConfig>,
    ) -> Result<IndexMap<String, Option<String>>> {
        // include_all_modes: the caller chose these secrets, and env="exec" or
        // env=false ones would otherwise be dropped by the shell-only filter
        let resolved = crate::daemon::resolve_batch_with_context(
            &self.context,
            &self.config,
            &self.profile,
            secrets,
            self.purpose,
            true,
        )
        .await?;
        let mut cache = self.cache.write().await;
        let mut values = IndexMap::new();
        for (key, value) in resolved {
            let value = cache.entry(key.clone()).or_insert(value).clone();
            values.insert(key, value);
        }
        Ok(values)
    }

    /// Resolve one secret on demand and cache it, absent or not, so an absent
    /// optional secret doesn't trigger auth again
    pub async fn resolve(&self, name: &str) -> Result<Option<String>> {
        if let Some(value) = self.cached(name).await {
            return Ok(value);
        }
        let Some(secret) = self.secrets().get(name).cloned() else {
            return Ok(None);
        };
        let single: IndexMap<String, SecretConfig> =
            [(name.to_string(), secret)].into_iter().collect();
        let resolved = crate::daemon::resolve_batch_with_context(
            &self.context,
            &self.config,
            &self.profile,
            &single,
            self.purpose,
            true,
        )
        .await?;
        let value = resolved.into_iter().next().and_then(|(_, v)| v);
        let mut cache = self.cache.write().await;
        // Another call may have cached it while this one resolved
        Ok(cache.entry(name.to_string()).or_insert(value).clone())
    }

    /// Load the config from disk, as it is now
    pub fn load_config(&self) -> Result<Config> {
        Config::load_smart(&self.config_path)
    }

    /// Resolve `name` from `config` (freshly loaded) the way a new session
    /// would, and use its value if it has one. Going through `get_secrets` and
    /// the resolver applies the top-level `env` default and settings such as
    /// `json_path`.
    pub async fn load(&self, config: &Config, name: &str) -> Result<bool> {
        let Some(secret) = config.get_secrets(&self.profile)?.shift_remove(name) else {
            return Ok(false);
        };
        let single: IndexMap<String, SecretConfig> =
            [(name.to_string(), secret.clone())].into_iter().collect();
        let resolved = crate::daemon::resolve_batch_with_context(
            &self.context,
            config,
            &self.profile,
            &single,
            self.purpose,
            true,
        )
        .await?;
        match resolved.into_iter().next().and_then(|(_, value)| value) {
            Some(value) => {
                self.add(name, secret, value).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Evict `name` from the daemon this session resolves through. A remote
    /// provider keeps the same reference when a value is replaced, so the
    /// daemon would otherwise keep serving the old value.
    pub async fn evict_from_daemon(&self, config: &Config, name: &str) -> Result<()> {
        crate::daemon::refresh_with_context(
            &self.context,
            config,
            std::slice::from_ref(&name.to_string()),
        )
        .await
    }

    /// The profile a new value is written to
    pub fn write_profile(&self) -> Result<String> {
        Config::resolve_write_profile(&self.profile, self.write_profile.as_deref())
    }

    /// The config file a new value is written to, as `fnox set` would pick it
    pub fn target_path(&self) -> Result<PathBuf> {
        local_target_path(
            &self.config_path,
            &self.profile,
            self.write_profile.as_deref(),
        )
    }

    /// The provider a new value for `name` would be stored with, refusing one
    /// that would leave it in plain text in the config
    pub async fn storage_provider(&self, config: &Config, name: &str) -> Result<StorageProvider> {
        let write_profile = self.write_profile()?;
        let write_stack = std::slice::from_ref(&write_profile);
        let effective = config.get_secret(write_stack, name)?.cloned();
        let Some(provider) = storage_provider(config, &write_profile, None, effective.as_ref())?
        else {
            return Ok(StorageProvider::Refused(format!(
                "Secret '{name}' has no provider and the config sets no default_provider, so fnox would store it in plain text. Ask the user to set default_provider."
            )));
        };
        let providers = config.get_providers(write_stack)?;
        let Some(provider_config) = providers.get(&provider) else {
            return Ok(StorageProvider::Refused(format!(
                "Provider '{provider}' not found in configuration"
            )));
        };
        let capabilities = crate::providers::get_provider_resolved(
            config,
            write_stack,
            &provider,
            provider_config,
        )
        .await?
        .capabilities();
        if !stores_securely(provider_config, &capabilities) {
            return Ok(StorageProvider::Refused(format!(
                "Provider '{provider}' would leave '{name}' in plain text in the config. Ask the user to set default_provider to a provider that encrypts values or stores them remotely."
            )));
        }
        Ok(StorageProvider::Secure(provider))
    }

    /// Check that `value` fits the `json_path` or `line` setting of `name` in
    /// `config`, so storing it can't replace a working value with one that
    /// can't be read
    pub fn check_value_fits(&self, config: &Config, name: &str, value: &str) -> Result<()> {
        // Check the secret as the active profiles read it and as the write
        // profile, which `--write-profile` may set to another profile, stores it
        let write_profile = self.write_profile()?;
        let read = config.get_secrets(&self.profile)?.shift_remove(name);
        let written = config
            .get_secret(std::slice::from_ref(&write_profile), name)?
            .cloned();
        for secret in read.iter().chain(written.iter()) {
            if secret.json_path.is_some() || secret.line.is_some() {
                crate::secret_resolver::apply_post_processing(value.to_string(), secret)?;
            }
        }
        Ok(())
    }

    /// Held while a value is rechecked and stored
    pub fn store_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.store_lock
    }

    /// Store `value` for `name`, as `fnox set` would, into `target`: the file
    /// [`Self::target_path`] picked when the user was asked, which they were
    /// shown. Plain text is refused.
    pub async fn save(
        &self,
        config: Config,
        name: &str,
        value: String,
        target: &Path,
    ) -> Result<()> {
        let set = SetCommand {
            key: Some(name.to_string()),
            value: Some(value),
            description: None,
            global: false,
            key_name: None,
            dry_run: false,
            provider: None,
            base64_encode: false,
            default: None,
            file: None,
            force: false,
            from_file: None,
            generate: false,
            generate_type: GenerateKind::Password,
            if_missing: None,
            length: None,
            show: false,
            source: None,
        };
        set.store_at(
            config,
            &self.profile,
            self.write_profile.as_deref(),
            target,
            true,
        )
        .await?;
        Ok(())
    }

    /// Load a value [`Self::save`] just stored in `target`, so the session
    /// uses it
    pub async fn reload_stored(&self, name: &str, target: &Path) -> Result<()> {
        let config = self.load_config()?;
        self.evict_from_daemon(&config, name).await?;
        if !self.load(&config, name).await? {
            return Err(FnoxError::Config("it resolves to no value".into()));
        }
        // Another file that takes precedence may define the secret too, such
        // as one created while the page was open; the stored value is then
        // not the one in use
        let source = self
            .secrets()
            .get(name)
            .and_then(|secret| secret.source_path.clone());
        if let Some(source) = source {
            let same = |a: &Path, b: &Path| {
                a == b
                    || std::fs::canonicalize(a)
                        .ok()
                        .zip(std::fs::canonicalize(b).ok())
                        .is_some_and(|(a, b)| a == b)
            };
            if !same(&source, target) {
                return Err(FnoxError::Config(format!(
                    "'{name}' is read from {}, which takes precedence over {}, so the new value isn't in use",
                    source.display(),
                    target.display()
                )));
            }
        }
        Ok(())
    }
}
