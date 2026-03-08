use crate::config::Config;
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::{self, ProviderCapability};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Default lease duration when none is specified
pub const DEFAULT_LEASE_DURATION: &str = "15m";

/// Buffer in seconds before expiry when a cached lease is no longer considered reusable
pub const LEASE_REUSE_BUFFER_SECS: i64 = 300;

/// A record of an issued lease, stored in the lease ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub lease_id: String,
    pub backend_name: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_credentials: Option<IndexMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_provider: Option<String>,
    /// Hash of the backend config at lease creation time, used to invalidate
    /// cached credentials when the config changes (e.g., role ARN rotation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

/// The lease ledger, tracking all issued leases
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeaseLedger {
    #[serde(default)]
    pub leases: Vec<LeaseRecord>,
}

/// RAII guard for the ledger file lock. The lock is released when dropped.
pub struct LedgerLockGuard {
    _lock: fslock::LockFile,
}

/// Determine the project directory for scoping the lease ledger.
///
/// Uses `Config::project_dir` (the nearest directory to cwd containing a config
/// file, set during recursive loading) when available. Falls back to resolving
/// `config_path` against cwd for non-recursive loads (explicit `--config` flag).
pub fn project_dir_from_config(config: &crate::config::Config, config_path: &Path) -> PathBuf {
    if let Some(ref dir) = config.project_dir {
        return dir.clone();
    }
    // Fallback for explicit --config paths
    let resolved = if config_path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(config_path))
            .unwrap_or_else(|_| config_path.to_path_buf())
    } else {
        config_path.to_path_buf()
    };
    resolved
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Hash a project directory path to produce a unique ledger filename.
/// Uses blake3 for stability across Rust toolchain upgrades (DefaultHasher
/// is explicitly not guaranteed to be stable across releases).
fn hash_project_dir(project_dir: &Path) -> String {
    let hash = blake3::hash(project_dir.to_string_lossy().as_bytes());
    hash.to_hex()[..16].to_string()
}

impl LeaseLedger {
    /// Path to the lease ledger file, scoped to a project directory.
    /// Uses `~/.local/state/fnox/leases/` (XDG state dir).
    fn ledger_path(project_dir: &Path) -> PathBuf {
        let hash = hash_project_dir(project_dir);
        env::FNOX_STATE_DIR
            .join("leases")
            .join(format!("{hash}.toml"))
    }

    /// Acquire an exclusive file lock for the ledger.
    /// Returns a guard that releases the lock on drop.
    ///
    /// Locks a separate `.lock` sentinel file rather than the data file itself,
    /// because `save()` uses atomic rename which replaces the data file's inode.
    /// Locking the data file directly would break mutual exclusion: after rename,
    /// new processes would lock the new inode while the old process holds the old one.
    pub fn lock(project_dir: &Path) -> Result<LedgerLockGuard> {
        let ledger_path = Self::ledger_path(project_dir);
        let lock_path = ledger_path.with_extension("lock");
        let lock = xx::fslock::FSLock::new(&lock_path)
            .lock()
            .map_err(|e| FnoxError::Config(format!("Failed to acquire ledger lock: {e}")))?;
        Ok(LedgerLockGuard { _lock: lock })
    }

    /// Load the lease ledger from disk, creating an empty one if it doesn't exist.
    /// The ledger is scoped to the project directory (parent of the config file).
    /// Caller should hold a `LedgerLockGuard` when performing load → mutate → save.
    pub fn load(project_dir: &Path) -> Result<Self> {
        let path = Self::ledger_path(project_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path).map_err(|e| FnoxError::ConfigReadFailed {
            path: path.clone(),
            source: e,
        })?;
        let ledger: Self = toml_edit::de::from_str(&content)
            .map_err(|e| FnoxError::ConfigParseError { source: e })?;
        Ok(ledger)
    }

    /// Save the lease ledger to disk, pruning stale entries first
    pub fn save(&self, project_dir: &Path) -> Result<()> {
        let path = Self::ledger_path(project_dir);
        // Ensure leases directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| FnoxError::CreateDirFailed {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        // Compact: drop entries that are revoked or expired more than 24h ago.
        // For records with no expiry (e.g., command backend with no expires_at),
        // use created_at + 24h as a staleness bound to prevent unbounded growth.
        let cutoff = Utc::now() - chrono::Duration::hours(24);
        let mut compacted = self.clone();
        compacted.leases.retain(|r| {
            if r.revoked {
                // Keep revoked records for audit visibility only if they have
                // an expiry within the window. Revoked records with no expiry
                // use created_at + 24h as the cutoff.
                return match r.expires_at {
                    Some(exp) => exp > cutoff,
                    None => r.created_at > cutoff,
                };
            }
            match r.expires_at {
                Some(exp) => exp > cutoff,
                // No expiry: prune if created more than 24h ago
                None => r.created_at > cutoff,
            }
        });
        let content = toml_edit::ser::to_string_pretty(&compacted)
            .map_err(|e| FnoxError::ConfigSerializeError { source: e })?;
        // Atomic write: write to a temp file then rename, so readers never see
        // a partially-written or truncated ledger (crash safety).
        let tmp_path = path.with_extension("toml.tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, content.as_bytes()))
                .map_err(|e| FnoxError::ConfigWriteFailed {
                    path: tmp_path.clone(),
                    source: e,
                })?;
        }
        #[cfg(not(unix))]
        fs::write(&tmp_path, &content).map_err(|e| FnoxError::ConfigWriteFailed {
            path: tmp_path.clone(),
            source: e,
        })?;
        fs::rename(&tmp_path, &path).map_err(|e| FnoxError::ConfigWriteFailed {
            path: path.clone(),
            source: e,
        })?;
        Ok(())
    }

    /// Add a new lease record to the ledger
    pub fn add(&mut self, record: LeaseRecord) {
        self.leases.push(record);
    }

    /// Mark a lease as revoked by ID, clearing any cached credentials
    pub fn mark_revoked(&mut self, lease_id: &str) -> bool {
        for record in &mut self.leases {
            if record.lease_id == lease_id {
                record.revoked = true;
                record.cached_credentials = None;
                record.encryption_provider = None;
                return true;
            }
        }
        false
    }

    /// Get all active (non-revoked, non-expired) leases
    pub fn active_leases(&self) -> Vec<&LeaseRecord> {
        let now = Utc::now();
        self.leases
            .iter()
            .filter(|r| !r.revoked && r.expires_at.is_none_or(|exp| exp > now))
            .collect()
    }

    /// Get all expired (non-revoked) leases
    pub fn expired_leases(&self) -> Vec<&LeaseRecord> {
        let now = Utc::now();
        self.leases
            .iter()
            .filter(|r| !r.revoked && r.expires_at.is_some_and(|exp| exp <= now))
            .collect()
    }

    /// Find a lease by ID
    pub fn find(&self, lease_id: &str) -> Option<&LeaseRecord> {
        self.leases.iter().find(|r| r.lease_id == lease_id)
    }

    /// Find a reusable cached lease for the given backend name and config hash.
    /// Returns the lease with the latest expiry that is still valid (with buffer).
    /// Never-expiring leases (expires_at: None) are ranked highest.
    /// Leases with a mismatched config_hash are skipped to prevent returning
    /// stale credentials after backend config changes (e.g., role ARN rotation).
    pub fn find_reusable(&self, backend_name: &str, config_hash: &str) -> Option<&LeaseRecord> {
        self.leases
            .iter()
            .filter(|r| {
                r.backend_name == backend_name
                    && r.is_reusable()
                    && r.config_hash.as_deref().is_none_or(|h| h == config_hash)
            })
            .max_by_key(|r| match r.expires_at {
                None => DateTime::<Utc>::MAX_UTC,
                Some(exp) => exp,
            })
    }
}

impl LeaseRecord {
    /// Check if this lease can be reused: not revoked, has cached credentials,
    /// and expires_at minus buffer is still in the future.
    pub fn is_reusable(&self) -> bool {
        if self.revoked || self.cached_credentials.is_none() {
            return false;
        }
        match self.expires_at {
            Some(exp) => {
                let buffer = chrono::Duration::seconds(LEASE_REUSE_BUFFER_SECS);
                exp - buffer > Utc::now()
            }
            None => true, // No expiry means it's always valid
        }
    }
}

/// RAII guard that removes temporary process env vars on drop.
/// Ensures cleanup on all exit paths, including early returns from `?`.
#[derive(Default)]
pub struct TempEnvGuard {
    pub keys: Vec<String>,
}

impl Drop for TempEnvGuard {
    fn drop(&mut self) {
        for key in &self.keys {
            // TODO: unsafe remove_var on a multi-threaded Tokio runtime is
            // technically UB. Refactor to pass credentials explicitly.
            unsafe { std::env::remove_var(key) };
        }
    }
}

/// Parse a human-readable duration string (e.g., "15m", "1h", "2h30m")
pub fn parse_duration(s: &str) -> Result<std::time::Duration> {
    let s = s.trim();
    let mut total_secs: u64 = 0;
    let mut current_num = String::new();

    for c in s.chars() {
        if c.is_ascii_digit() {
            current_num.push(c);
        } else {
            let num: u64 = current_num
                .parse()
                .map_err(|_| FnoxError::Config(format!("Invalid duration: '{s}'")))?;
            current_num.clear();

            match c {
                's' => total_secs += num,
                'm' => total_secs += num * 60,
                'h' => total_secs += num * 3600,
                'd' => total_secs += num * 86400,
                _ => {
                    return Err(FnoxError::Config(format!(
                        "Invalid duration unit '{c}' in '{s}'. Use s, m, h, or d"
                    )));
                }
            }
        }
    }

    // If there's a trailing number with no unit, treat as seconds
    if !current_num.is_empty() {
        let num: u64 = current_num
            .parse()
            .map_err(|_| FnoxError::Config(format!("Invalid duration: '{s}'")))?;
        total_secs += num;
    }

    if total_secs == 0 {
        return Err(FnoxError::Config(
            "Duration must be greater than 0".to_string(),
        ));
    }

    Ok(std::time::Duration::from_secs(total_secs))
}

/// Result of searching for an encryption provider
pub enum EncryptionProviderResult {
    /// No encryption-capable default_provider is configured
    NotConfigured,
    /// An encryption provider was found and instantiated
    Available(String, Box<dyn providers::Provider>),
    /// An encryption provider is configured but failed to instantiate
    Unavailable(String, FnoxError),
}

/// Find an encryption provider if one is configured (default_provider with Encryption capability)
pub async fn find_encryption_provider(config: &Config, profile: &str) -> EncryptionProviderResult {
    let provider_name = match config.get_default_provider(profile) {
        Ok(Some(name)) => name,
        _ => return EncryptionProviderResult::NotConfigured,
    };

    let providers_map = config.get_providers(profile);
    let provider_config = match providers_map.get(&provider_name) {
        Some(c) => c,
        None => return EncryptionProviderResult::NotConfigured,
    };

    let provider =
        match providers::get_provider_resolved(config, profile, &provider_name, provider_config)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                return EncryptionProviderResult::Unavailable(provider_name, e);
            }
        };

    if provider
        .capabilities()
        .contains(&ProviderCapability::Encryption)
    {
        EncryptionProviderResult::Available(provider_name, provider)
    } else {
        EncryptionProviderResult::NotConfigured
    }
}

/// Create a lease, cache credentials, and record it in the ledger.
/// Shared between `fnox exec` and `fnox lease create` to avoid duplication.
#[allow(clippy::too_many_arguments)]
pub async fn create_and_record_lease(
    backend: &dyn crate::lease_backends::LeaseBackend,
    backend_name: &str,
    label: &str,
    duration: std::time::Duration,
    config_hash: String,
    config: &Config,
    profile: &str,
    ledger: &mut LeaseLedger,
    project_dir: &Path,
) -> Result<crate::lease_backends::Lease> {
    let result = backend.create_lease(duration, label).await?;

    let (cached_credentials, encryption_provider) =
        cache_credentials(config, profile, &result.credentials, &result.lease_id).await;

    ledger.add(LeaseRecord {
        lease_id: result.lease_id.clone(),
        backend_name: backend_name.to_string(),
        label: label.to_string(),
        created_at: Utc::now(),
        expires_at: result.expires_at,
        revoked: false,
        cached_credentials,
        encryption_provider,
        config_hash: Some(config_hash),
    });
    if let Err(save_err) = ledger.save(project_dir) {
        tracing::warn!(
            "Lease '{}' created for backend '{}' but ledger save failed: {}. \
             This lease is untracked and must be revoked manually.",
            result.lease_id,
            backend_name,
            save_err
        );
    }

    Ok(result)
}

/// Set resolved secrets as process env vars so lease backend SDKs can find
/// master credentials during lease creation. Returns temp files that must be
/// kept alive for the duration of the operation (for `as_file` secrets).
///
/// # Safety
/// Uses `unsafe { std::env::set_var }` which is technically UB on a
/// multi-threaded Tokio runtime. TODO: refactor to pass credentials explicitly.
pub fn set_secrets_as_env(
    resolved_secrets: &IndexMap<String, Option<String>>,
    profile_secrets: &IndexMap<String, crate::config::SecretConfig>,
    guard: &mut TempEnvGuard,
) -> Result<Vec<tempfile::NamedTempFile>> {
    let mut temp_files = Vec::new();
    for (key, value) in resolved_secrets {
        if let Some(value) = value {
            let env_value = if profile_secrets.get(key).is_some_and(|sc| sc.as_file) {
                let temp_file = crate::temp_file_secrets::create_ephemeral_secret_file(key, value)?;
                let path = temp_file.path().to_string_lossy().to_string();
                temp_files.push(temp_file);
                path
            } else {
                value.clone()
            };
            unsafe { std::env::set_var(key, &env_value) };
            guard.keys.push(key.clone());
        }
    }
    Ok(temp_files)
}

/// Encrypt credential values using an encryption provider
pub async fn encrypt_credentials(
    provider: &dyn providers::Provider,
    credentials: &IndexMap<String, String>,
) -> Result<IndexMap<String, String>> {
    let mut encrypted = IndexMap::new();
    for (key, value) in credentials {
        let enc = provider.encrypt(value).await?;
        encrypted.insert(key.clone(), enc);
    }
    Ok(encrypted)
}

/// Decrypt cached credential values using an encryption provider
pub async fn decrypt_credentials(
    provider: &dyn providers::Provider,
    cached: &IndexMap<String, String>,
) -> Result<IndexMap<String, String>> {
    let mut decrypted = IndexMap::new();
    for (key, value) in cached {
        let dec = provider.get_secret(value).await?;
        decrypted.insert(key.clone(), dec);
    }
    Ok(decrypted)
}

/// Determine how to cache credentials: encrypt if a provider is available,
/// skip caching if the provider is configured but unavailable, or store
/// plaintext if no encryption provider is configured.
pub async fn cache_credentials(
    config: &Config,
    profile: &str,
    credentials: &IndexMap<String, String>,
    lease_id: &str,
) -> (Option<IndexMap<String, String>>, Option<String>) {
    match find_encryption_provider(config, profile).await {
        EncryptionProviderResult::Available(enc_name, provider) => {
            match encrypt_credentials(provider.as_ref(), credentials).await {
                Ok(encrypted) => {
                    tracing::debug!("Caching encrypted credentials for lease '{}'", lease_id);
                    (Some(encrypted), Some(enc_name))
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to encrypt credentials for caching: {}, skipping cache",
                        e
                    );
                    (None, None)
                }
            }
        }
        EncryptionProviderResult::Unavailable(enc_name, e) => {
            tracing::warn!(
                "Encryption provider '{}' configured but unavailable: {}, skipping credential cache",
                enc_name,
                e
            );
            (None, None)
        }
        EncryptionProviderResult::NotConfigured => {
            tracing::debug!(
                "No encryption provider, caching plaintext credentials for lease '{}'",
                lease_id
            );
            (Some(credentials.clone()), None)
        }
    }
}

/// Resolve a lease backend into credentials, reusing cached credentials when available.
/// Shared between `fnox exec` and `fnox get`.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_lease(
    name: &str,
    lease_config: &crate::lease_backends::LeaseBackendConfig,
    config: &Config,
    profile: &str,
    project_dir: &Path,
    ledger: &mut LeaseLedger,
    prereq_missing: Option<&str>,
    label_prefix: &str,
) -> Result<IndexMap<String, String>> {
    let config_hash = lease_config.config_hash();
    if let Some(cached_lease) = ledger.find_reusable(name, &config_hash)
        && let Some(ref cached_creds) = cached_lease.cached_credentials
    {
        if let Some(ref enc_provider_name) = cached_lease.encryption_provider {
            match find_encryption_provider(config, profile).await {
                EncryptionProviderResult::Available(found_name, provider)
                    if found_name == *enc_provider_name =>
                {
                    match decrypt_credentials(provider.as_ref(), cached_creds).await {
                        Ok(decrypted) => {
                            tracing::debug!(
                                "Reusing cached encrypted lease '{}' for backend '{}'",
                                cached_lease.lease_id,
                                name
                            );
                            return Ok(decrypted);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to decrypt cached lease '{}': {}, creating fresh lease",
                                cached_lease.lease_id,
                                e
                            );
                        }
                    }
                }
                _ => {
                    tracing::warn!(
                        "Encryption provider '{}' not available for cached lease '{}', creating fresh lease",
                        enc_provider_name,
                        cached_lease.lease_id
                    );
                }
            }
        } else {
            tracing::debug!(
                "Reusing cached plaintext lease '{}' for backend '{}'",
                cached_lease.lease_id,
                name
            );
            return Ok(cached_creds.clone());
        }
    }

    if let Some(missing) = prereq_missing {
        return Err(FnoxError::Config(format!(
            "Lease '{}': cached credentials could not be decrypted and \
             prerequisites are missing: {}\n\
             Run 'fnox lease create -i {}' to set up credentials interactively.",
            name, missing, name
        )));
    }
    let backend = lease_config.create_backend()?;

    let duration_str = lease_config.duration().unwrap_or(DEFAULT_LEASE_DURATION);
    let duration = parse_duration(duration_str)?;

    let max_duration = backend.max_lease_duration();
    if duration > max_duration {
        return Err(FnoxError::Config(format!(
            "Lease duration '{}' for '{}' exceeds maximum {:?}",
            duration_str, name, max_duration
        )));
    }

    let label = format!("fnox-{}-{}", label_prefix, name);
    let result = create_and_record_lease(
        backend.as_ref(),
        name,
        &label,
        duration,
        config_hash,
        config,
        profile,
        ledger,
        project_dir,
    )
    .await?;

    tracing::debug!(
        "Created lease '{}' for backend '{}' (expires {:?})",
        result.lease_id,
        name,
        result.expires_at
    );

    Ok(result.credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("15m").unwrap().as_secs(), 900);
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap().as_secs(), 3600);
    }

    #[test]
    fn test_parse_duration_combined() {
        assert_eq!(parse_duration("2h30m").unwrap().as_secs(), 9000);
    }

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap().as_secs(), 30);
    }

    #[test]
    fn test_parse_duration_bare_number() {
        assert_eq!(parse_duration("300").unwrap().as_secs(), 300);
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("0m").is_err());
        assert!(parse_duration("abc").is_err());
    }
}
