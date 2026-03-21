//! Auto-sync cache for resolved secrets.
//!
//! Stores encrypted copies of resolved secret values on disk so that subsequent
//! calls to `fnox export`, `fnox exec`, and `fnox hook-env` can return them
//! without making network round-trips to remote providers.
//!
//! The cache reuses the same encryption primitives as `fnox sync`
//! (`provider.encrypt()` / `provider.get_secret()`), the same `SyncConfig`
//! data structure concept, and feeds into the same resolver code path.
//!
//! ## Cache location
//!
//! ```text
//! ~/.local/state/fnox/cache/<project-hash>.toml         # cache data
//! ~/.local/state/fnox/cache/<project-hash>.lock          # file lock (sentinel)
//! ~/.local/state/fnox/cache/<project-hash>.refreshing    # background refresh lock
//! ```

use crate::config::Config;
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers;
use crate::settings::Settings;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, io::Write};

/// Cache entry stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub metadata: CacheMetadata,
    pub secrets: IndexMap<String, String>,
}

/// Cache metadata for validation and TTL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    /// BLAKE3 hash of config state (files + mtimes + profile + env vars)
    pub cache_key: String,
    /// UTC milliseconds when the cache was created
    pub created_at: u64,
    /// Name of the encryption provider used (empty string if plaintext)
    pub encryption_provider: String,
    /// Active profile name
    pub profile: String,
}

/// Result of checking cache validity
#[derive(Debug)]
pub enum CacheStatus {
    /// Cache is fresh (within soft TTL)
    Fresh(CacheEntry),
    /// Cache is stale but usable (between soft and hard TTL)
    Stale(CacheEntry),
    /// Cache is expired (past hard TTL) or key mismatch
    Expired,
    /// No cache file exists
    Missing,
}

/// Parse a duration string like "15m", "4h", "30s", "2h30m" into a Duration.
pub fn parse_duration_string(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }

    let mut total_secs: u64 = 0;
    let mut current_num = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            let num: u64 = current_num
                .parse()
                .map_err(|_| format!("invalid number in duration: '{current_num}'"))?;
            current_num.clear();

            match ch {
                's' => total_secs += num,
                'm' => total_secs += num * 60,
                'h' => total_secs += num * 3600,
                'd' => total_secs += num * 86400,
                _ => return Err(format!("unknown duration unit: '{ch}'")),
            }
        }
    }

    // Handle bare numbers (treat as seconds)
    if !current_num.is_empty() {
        let num: u64 = current_num
            .parse()
            .map_err(|_| format!("invalid number in duration: '{current_num}'"))?;
        total_secs += num;
    }

    if total_secs == 0 {
        return Err("duration must be greater than zero".to_string());
    }

    Ok(Duration::from_secs(total_secs))
}

// ---------------------------------------------------------------------------
// Cache file paths
// ---------------------------------------------------------------------------

/// Hash a project directory path to produce a unique cache filename.
fn hash_project_dir(project_dir: &Path) -> String {
    let hash = blake3::hash(project_dir.to_string_lossy().as_bytes());
    hash.to_hex()[..16].to_string()
}

fn cache_dir() -> PathBuf {
    env::FNOX_STATE_DIR.join("cache")
}

fn cache_path(project_dir: &Path) -> PathBuf {
    let hash = hash_project_dir(project_dir);
    cache_dir().join(format!("{hash}.toml"))
}

fn cache_refreshing_path(project_dir: &Path) -> PathBuf {
    cache_path(project_dir).with_extension("refreshing")
}

// ---------------------------------------------------------------------------
// Cache key computation
// ---------------------------------------------------------------------------

/// Compute a BLAKE3 cache key from the current config state.
///
/// Incorporates:
/// - All config file paths and mtimes in the hierarchy
/// - Active profile name
/// - All `FNOX_*` environment variables
pub fn compute_cache_key(project_dir: &Path, profile: &str) -> String {
    use std::collections::BTreeMap;

    let mut hasher = blake3::Hasher::new();

    // 1. Config file paths and mtimes
    let profile_name = crate::settings::Settings::get().profile.clone();
    let filenames = crate::config::all_config_filenames(Some(&profile_name));

    let mut current = project_dir.to_path_buf();
    loop {
        for filename in &filenames {
            let config_path = current.join(filename);
            if let Ok(metadata) = fs::metadata(&config_path)
                && let Ok(modified) = metadata.modified()
                && let Ok(duration) = modified.duration_since(UNIX_EPOCH)
            {
                hasher.update(config_path.to_string_lossy().as_bytes());
                hasher.update(&duration.as_millis().to_le_bytes());
            }
        }
        if !current.pop() {
            break;
        }
    }

    // Also include global config
    let global = Config::global_config_path();
    if let Ok(metadata) = fs::metadata(&global)
        && let Ok(modified) = metadata.modified()
        && let Ok(duration) = modified.duration_since(UNIX_EPOCH)
    {
        hasher.update(global.to_string_lossy().as_bytes());
        hasher.update(&duration.as_millis().to_le_bytes());
    }

    // 2. Active profile
    hasher.update(profile.as_bytes());

    // 3. FNOX_* environment variables (sorted for determinism)
    let mut env_vars: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in std::env::vars() {
        if key.starts_with("FNOX_") {
            env_vars.insert(key, value);
        }
    }
    for (key, value) in &env_vars {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\0");
    }

    hasher.finalize().to_hex()[..32].to_string()
}

// ---------------------------------------------------------------------------
// Enablement check
// ---------------------------------------------------------------------------

/// Determine whether caching is enabled for the current invocation.
///
/// Returns `Some(encryption_provider_name)` if caching is enabled,
/// or `None` if disabled.
///
/// - `"auto"` (default): enabled if a default encryption provider with
///   Encryption capability is configured
/// - `"true"`: force enable (plaintext if no encryption provider)
/// - `"false"`: force disable
pub fn is_cache_enabled(config: &Config, profile: &str) -> Option<String> {
    // Per-project opt-out
    if config.cache == Some(false) {
        tracing::debug!("cache disabled by config: cache = false");
        return None;
    }

    let settings = Settings::get();
    let mode = settings.cache.to_lowercase();

    match mode.as_str() {
        "false" | "0" | "off" | "no" => {
            tracing::debug!("cache disabled by FNOX_CACHE={}", mode);
            None
        }
        "true" | "1" | "on" | "yes" => {
            // Force enable — find encryption provider if available, allow plaintext otherwise
            match find_encryption_provider(config, profile) {
                Some(name) => Some(name),
                None => {
                    tracing::debug!("cache force-enabled without encryption provider (plaintext)");
                    Some(String::new()) // empty string = plaintext mode
                }
            }
        }
        _ => {
            // "auto" or anything else: require encryption provider
            match find_encryption_provider(config, profile) {
                Some(name) => {
                    tracing::debug!("cache auto-enabled with encryption provider '{}'", name);
                    Some(name)
                }
                None => {
                    tracing::debug!(
                        "cache auto-disabled: no default encryption provider configured"
                    );
                    None
                }
            }
        }
    }
}

/// Find the default encryption provider name if one is configured and has
/// the Encryption capability.
fn find_encryption_provider(config: &Config, profile: &str) -> Option<String> {
    let default_provider = config.get_default_provider(profile).ok().flatten()?;
    let providers_map = config.get_providers(profile);
    let provider_config = providers_map.get(&default_provider)?;

    // Check if this provider type has Encryption capability by inspecting the
    // provider config type string. We cannot instantiate the provider here
    // (that would require async + potentially network), so we check the type.
    let ptype = provider_config.provider_type();
    match ptype {
        "age" | "aws-kms" | "azure-kms" | "gcp-kms" | "fido2" | "yubikey" => Some(default_provider),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Cache read
// ---------------------------------------------------------------------------

/// Check the cache status: fresh, stale, expired, or missing.
pub fn check_cache(project_dir: &Path, current_cache_key: &str) -> CacheStatus {
    let path = cache_path(project_dir);

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return CacheStatus::Missing,
    };

    let entry: CacheEntry = match toml_edit::de::from_str(&content) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("cache file corrupt, treating as missing: {}", e);
            return CacheStatus::Missing;
        }
    };

    // Check cache key
    if entry.metadata.cache_key != current_cache_key {
        tracing::debug!("cache key mismatch, treating as expired");
        return CacheStatus::Expired;
    }

    // Check TTL
    let settings = Settings::get();
    let soft_ttl =
        parse_duration_string(&settings.cache_soft_ttl).unwrap_or(Duration::from_secs(900));
    let hard_ttl =
        parse_duration_string(&settings.cache_hard_ttl).unwrap_or(Duration::from_secs(14400));

    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let age_millis = now_millis.saturating_sub(entry.metadata.created_at);
    let age = Duration::from_millis(age_millis);

    if age < soft_ttl {
        CacheStatus::Fresh(entry)
    } else if age < hard_ttl {
        CacheStatus::Stale(entry)
    } else {
        tracing::debug!("cache hard TTL exceeded ({:?} old)", age);
        CacheStatus::Expired
    }
}

/// Decrypt cached secret values using the specified encryption provider.
///
/// If `encryption_provider` is empty, values are stored as plaintext.
pub async fn decrypt_cache_entry(
    config: &Config,
    profile: &str,
    entry: &CacheEntry,
) -> Result<IndexMap<String, Option<String>>> {
    let provider_name = &entry.metadata.encryption_provider;

    if provider_name.is_empty() {
        // Plaintext mode — values are stored directly
        let result = entry
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();
        return Ok(result);
    }

    // Get the encryption provider for decryption
    let providers_map = config.get_providers(profile);
    let provider_config = match providers_map.get(provider_name) {
        Some(pc) => pc,
        None => {
            tracing::warn!(
                "cache encryption provider '{}' no longer configured, cache invalid",
                provider_name
            );
            return Err(FnoxError::Config(format!(
                "cache encryption provider '{}' not found",
                provider_name
            )));
        }
    };

    let provider =
        providers::get_provider_resolved(config, profile, provider_name, provider_config).await?;

    let mut result = IndexMap::new();
    // Decrypt using get_secrets_batch for efficiency
    let batch: Vec<(String, String)> = entry
        .secrets
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let batch_results = provider.get_secrets_batch(&batch).await;
    for (key, _ciphertext) in &batch {
        match batch_results.get(key) {
            Some(Ok(plaintext)) => {
                result.insert(key.clone(), Some(plaintext.clone()));
            }
            Some(Err(e)) => {
                tracing::warn!("failed to decrypt cached secret '{}': {}", key, e);
                // Return error to force a full refresh
                return Err(FnoxError::Config(format!(
                    "failed to decrypt cached secret '{}': {}",
                    key, e
                )));
            }
            None => {
                tracing::warn!("cached secret '{}' missing from batch results", key);
                return Err(FnoxError::Config(format!(
                    "cached secret '{}' missing from batch results",
                    key
                )));
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Cache write
// ---------------------------------------------------------------------------

/// Write resolved secrets to the cache file, encrypting with the given provider.
///
/// `encryption_provider_name` is empty for plaintext mode.
pub async fn write_cache(
    config: &Config,
    profile: &str,
    project_dir: &Path,
    cache_key: &str,
    encryption_provider_name: &str,
    resolved: &IndexMap<String, Option<String>>,
) -> Result<()> {
    let encrypted_secrets = if encryption_provider_name.is_empty() {
        // Plaintext mode
        resolved
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|val| (k.clone(), val.clone())))
            .collect()
    } else {
        // Encrypt each value
        let providers_map = config.get_providers(profile);
        let provider_config = match providers_map.get(encryption_provider_name) {
            Some(pc) => pc,
            None => {
                tracing::warn!(
                    "encryption provider '{}' not found, skipping cache write",
                    encryption_provider_name
                );
                return Ok(());
            }
        };

        let provider = providers::get_provider_resolved(
            config,
            profile,
            encryption_provider_name,
            provider_config,
        )
        .await?;

        let mut encrypted = IndexMap::new();
        for (key, value_opt) in resolved {
            if let Some(value) = value_opt {
                match provider.encrypt(value).await {
                    Ok(ciphertext) => {
                        encrypted.insert(key.clone(), ciphertext);
                    }
                    Err(e) => {
                        tracing::warn!("failed to encrypt secret '{}' for cache: {}", key, e);
                        // Skip this secret but continue with others
                    }
                }
            }
        }
        encrypted
    };

    if encrypted_secrets.is_empty() {
        tracing::debug!("no secrets to cache");
        return Ok(());
    }

    let entry = CacheEntry {
        metadata: CacheMetadata {
            cache_key: cache_key.to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            encryption_provider: encryption_provider_name.to_string(),
            profile: profile.to_string(),
        },
        secrets: encrypted_secrets,
    };

    write_cache_entry(project_dir, &entry)
}

/// Write a CacheEntry to disk atomically.
fn write_cache_entry(project_dir: &Path, entry: &CacheEntry) -> Result<()> {
    let path = cache_path(project_dir);

    // Ensure cache directory exists
    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(|e| FnoxError::CreateDirFailed {
        path: dir.clone(),
        source: e,
    })?;

    // Set directory permissions (0700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        let _ = fs::set_permissions(&dir, perms);
    }

    let content = toml_edit::ser::to_string_pretty(entry)
        .map_err(|source| FnoxError::ConfigSerializeError { source })?;

    // Atomic write: temp file + rename
    let tmp_path = path.with_extension("toml.tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| FnoxError::ConfigWriteFailed {
                path: tmp_path.clone(),
                source: e,
            })?;
        file.write_all(content.as_bytes())
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

    tracing::debug!("cache written to {}", path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Cache invalidation
// ---------------------------------------------------------------------------

/// Invalidate (delete) the cache for a given project directory.
pub fn invalidate_cache(project_dir: &Path) {
    let path = cache_path(project_dir);
    if path.exists() {
        if let Err(e) = fs::remove_file(&path) {
            tracing::warn!("failed to invalidate cache at {}: {}", path.display(), e);
        } else {
            tracing::debug!("cache invalidated: {}", path.display());
        }
    }
}

/// Invalidate cache for the current working directory.
/// Used by write commands (set, sync, import, remove).
pub fn invalidate_cache_for_cwd() {
    if let Ok(cwd) = std::env::current_dir() {
        // Try to find the project dir the same way lease does
        let project_dir = find_project_dir_from_cwd(&cwd);
        invalidate_cache(&project_dir);
    }
}

/// Find the project directory from cwd by looking for config files.
fn find_project_dir_from_cwd(cwd: &Path) -> PathBuf {
    let profile = Settings::get().profile.clone();
    let filenames = crate::config::all_config_filenames(Some(&profile));

    let mut current = cwd.to_path_buf();
    loop {
        for filename in &filenames {
            if current.join(filename).exists() {
                return current;
            }
        }
        if !current.pop() {
            break;
        }
    }

    // Fallback to cwd
    cwd.to_path_buf()
}

// ---------------------------------------------------------------------------
// Background refresh
// ---------------------------------------------------------------------------

/// Spawn a detached background process to refresh the cache.
///
/// Uses a `.refreshing` lock file to prevent concurrent refresh processes.
/// The parent returns immediately.
pub fn spawn_background_refresh(project_dir: &Path) {
    let refreshing_path = cache_refreshing_path(project_dir);

    // Try to create the refreshing lock file (non-blocking)
    // If it already exists, another refresh is in progress — skip.
    match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&refreshing_path)
    {
        Ok(mut f) => {
            // Write PID for debugging
            let _ = write!(f, "{}", std::process::id());
        }
        Err(_) => {
            // Check if the existing lock is stale (older than 2 minutes)
            if let Ok(metadata) = fs::metadata(&refreshing_path)
                && let Ok(modified) = metadata.modified()
                && let Ok(age) = SystemTime::now().duration_since(modified)
            {
                if age > Duration::from_secs(120) {
                    // Stale lock — remove and retry
                    let _ = fs::remove_file(&refreshing_path);
                    tracing::debug!("removed stale refresh lock");
                } else {
                    tracing::debug!("background refresh already in progress, skipping");
                    return;
                }
            } else {
                tracing::debug!("background refresh lock exists, skipping");
                return;
            }
            // Try again after removing stale lock
            if fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&refreshing_path)
                .is_err()
            {
                return;
            }
        }
    }

    // Get the current exe path
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("cannot find current exe for background refresh: {}", e);
            let _ = fs::remove_file(&refreshing_path);
            return;
        }
    };

    // Get the project directory for cwd of the child process
    let project_dir_str = project_dir.to_string_lossy().to_string();

    // Spawn detached: `fnox cache refresh` with the project dir as cwd
    // We pass the project dir as an env var so the child can find it
    let result = std::process::Command::new(&exe)
        .arg("cache")
        .arg("refresh")
        .env("__FNOX_CACHE_PROJECT_DIR", &project_dir_str)
        .env(
            "__FNOX_CACHE_REFRESHING_PATH",
            refreshing_path.to_string_lossy().as_ref(),
        )
        .current_dir(&project_dir_str)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    match result {
        Ok(_) => {
            tracing::debug!("background cache refresh spawned");
        }
        Err(e) => {
            tracing::warn!("failed to spawn background cache refresh: {}", e);
            let _ = fs::remove_file(cache_refreshing_path(Path::new(&project_dir_str)));
        }
    }
}

// ---------------------------------------------------------------------------
// Cache status report (for doctor command)
// ---------------------------------------------------------------------------

/// Cache status information for the doctor command.
pub struct CacheReport {
    pub enabled: bool,
    pub encryption_provider: Option<String>,
    pub cache_file: Option<PathBuf>,
    pub age_seconds: Option<u64>,
    pub num_secrets: usize,
    pub plaintext_warning: bool,
}

/// Generate a cache status report for the doctor command.
pub fn cache_report(config: &Config, profile: &str, project_dir: &Path) -> CacheReport {
    let encryption_provider = is_cache_enabled(config, profile);
    let enabled = encryption_provider.is_some();
    let plaintext_warning = encryption_provider.as_deref() == Some("");

    let path = cache_path(project_dir);
    let (cache_file, age_seconds, num_secrets) = if path.exists() {
        let age = fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .map(|d| d.as_secs());

        let num = fs::read_to_string(&path)
            .ok()
            .and_then(|c| toml_edit::de::from_str::<CacheEntry>(&c).ok())
            .map(|e| e.secrets.len())
            .unwrap_or(0);

        (Some(path), age, num)
    } else {
        (None, None, 0)
    };

    CacheReport {
        enabled,
        encryption_provider: encryption_provider.filter(|s| !s.is_empty()),
        cache_file,
        age_seconds,
        num_secrets,
        plaintext_warning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::providers::ProviderConfig;
    use crate::spanned::SpannedValue;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Create a Config with an age encryption provider set as default.
    fn config_with_age_provider() -> Config {
        let mut config = Config::new();
        config.providers.insert(
            "age".to_string(),
            ProviderConfig::AgeEncryption {
                recipients: vec!["age1test".to_string()],
                key_file: Default::default(),
                auth_command: None,
            },
        );
        config.set_default_provider(Some("age".to_string()));
        config
    }

    /// Create a Config with only a plain (non-encryption) provider.
    fn config_with_plain_provider() -> Config {
        let mut config = Config::new();
        config.providers.insert(
            "plain".to_string(),
            ProviderConfig::Plain { auth_command: None },
        );
        config.set_default_provider(Some("plain".to_string()));
        config
    }

    /// Create a minimal CacheEntry for testing.
    fn make_cache_entry(cache_key: &str, age_millis: u64) -> CacheEntry {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut secrets = IndexMap::new();
        secrets.insert("DB_URL".to_string(), "encrypted-db-url".to_string());
        secrets.insert("API_KEY".to_string(), "encrypted-api-key".to_string());
        CacheEntry {
            metadata: CacheMetadata {
                cache_key: cache_key.to_string(),
                created_at: now.saturating_sub(age_millis),
                encryption_provider: "age".to_string(),
                profile: "default".to_string(),
            },
            secrets,
        }
    }

    /// Write a CacheEntry directly to a project dir's cache path.
    fn write_test_cache(project_dir: &Path, entry: &CacheEntry) {
        write_cache_entry(project_dir, entry).unwrap();
    }

    // -----------------------------------------------------------------------
    // parse_duration_string
    // -----------------------------------------------------------------------

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(
            parse_duration_string("15m").unwrap(),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(
            parse_duration_string("4h").unwrap(),
            Duration::from_secs(14400)
        );
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(
            parse_duration_string("30s").unwrap(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn parse_duration_combined() {
        assert_eq!(
            parse_duration_string("2h30m").unwrap(),
            Duration::from_secs(9000)
        );
        assert_eq!(
            parse_duration_string("1h15m30s").unwrap(),
            Duration::from_secs(4530)
        );
    }

    #[test]
    fn parse_duration_days() {
        assert_eq!(
            parse_duration_string("1d").unwrap(),
            Duration::from_secs(86400)
        );
    }

    #[test]
    fn parse_duration_bare_number_treated_as_seconds() {
        assert_eq!(
            parse_duration_string("60").unwrap(),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn parse_duration_whitespace_trimmed() {
        assert_eq!(
            parse_duration_string("  5m  ").unwrap(),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn parse_duration_rejects_empty() {
        assert!(parse_duration_string("").is_err());
    }

    #[test]
    fn parse_duration_rejects_zero() {
        assert!(parse_duration_string("0s").is_err());
        assert!(parse_duration_string("0m").is_err());
        assert!(parse_duration_string("0").is_err());
    }

    #[test]
    fn parse_duration_rejects_invalid_unit() {
        assert!(parse_duration_string("5x").is_err());
    }

    #[test]
    fn parse_duration_rejects_non_numeric() {
        assert!(parse_duration_string("abc").is_err());
    }

    // -----------------------------------------------------------------------
    // hash_project_dir
    // -----------------------------------------------------------------------

    #[test]
    fn hash_project_dir_different_paths_different_hashes() {
        let h1 = hash_project_dir(Path::new("/home/user/project-a"));
        let h2 = hash_project_dir(Path::new("/home/user/project-b"));
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_project_dir_fixed_length() {
        let h = hash_project_dir(Path::new("/some/long/deeply/nested/path/to/project"));
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn hash_project_dir_deterministic() {
        let p = Path::new("/home/user/my-project");
        assert_eq!(hash_project_dir(p), hash_project_dir(p));
    }

    // -----------------------------------------------------------------------
    // cache_path / cache_refreshing_path (via hash_project_dir)
    // -----------------------------------------------------------------------

    #[test]
    fn cache_path_ends_with_toml() {
        let p = cache_path(Path::new("/project"));
        assert!(p.extension().is_some_and(|e| e == "toml"));
    }

    #[test]
    fn cache_refreshing_path_ends_with_refreshing() {
        let p = cache_refreshing_path(Path::new("/project"));
        assert!(p.extension().is_some_and(|e| e == "refreshing"));
    }

    #[test]
    fn cache_path_different_projects_different_files() {
        let p1 = cache_path(Path::new("/project-a"));
        let p2 = cache_path(Path::new("/project-b"));
        assert_ne!(p1, p2);
    }

    // -----------------------------------------------------------------------
    // CacheEntry serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn cache_entry_toml_roundtrip() {
        let entry = make_cache_entry("test-key-abc", 0);
        let serialized = toml_edit::ser::to_string_pretty(&entry).unwrap();
        let deserialized: CacheEntry = toml_edit::de::from_str(&serialized).unwrap();

        assert_eq!(deserialized.metadata.cache_key, "test-key-abc");
        assert_eq!(deserialized.metadata.encryption_provider, "age");
        assert_eq!(deserialized.metadata.profile, "default");
        assert_eq!(deserialized.secrets.len(), 2);
        assert_eq!(deserialized.secrets["DB_URL"], "encrypted-db-url");
        assert_eq!(deserialized.secrets["API_KEY"], "encrypted-api-key");
    }

    #[test]
    fn cache_entry_preserves_secret_order() {
        let mut secrets = IndexMap::new();
        secrets.insert("ZZZ".to_string(), "val-z".to_string());
        secrets.insert("AAA".to_string(), "val-a".to_string());
        secrets.insert("MMM".to_string(), "val-m".to_string());
        let entry = CacheEntry {
            metadata: CacheMetadata {
                cache_key: "k".to_string(),
                created_at: 0,
                encryption_provider: String::new(),
                profile: "default".to_string(),
            },
            secrets,
        };
        let serialized = toml_edit::ser::to_string_pretty(&entry).unwrap();
        let deserialized: CacheEntry = toml_edit::de::from_str(&serialized).unwrap();
        let keys: Vec<&String> = deserialized.secrets.keys().collect();
        assert_eq!(keys, vec!["ZZZ", "AAA", "MMM"]);
    }

    // -----------------------------------------------------------------------
    // write_cache_entry + read (check_cache)
    // -----------------------------------------------------------------------

    #[test]
    fn write_and_read_cache_fresh() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("my-key", 0);
        write_test_cache(dir.path(), &entry);

        match check_cache(dir.path(), "my-key") {
            CacheStatus::Fresh(e) => {
                assert_eq!(e.metadata.cache_key, "my-key");
                assert_eq!(e.secrets.len(), 2);
            }
            other => panic!("expected Fresh, got {:?}", status_name(&other)),
        }
    }

    #[test]
    fn check_cache_missing_when_no_file() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            check_cache(dir.path(), "any-key"),
            CacheStatus::Missing
        ));
    }

    #[test]
    fn check_cache_expired_on_key_mismatch() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("original-key", 0);
        write_test_cache(dir.path(), &entry);

        assert!(matches!(
            check_cache(dir.path(), "different-key"),
            CacheStatus::Expired
        ));
    }

    #[test]
    fn check_cache_stale_after_soft_ttl() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        // Default soft TTL is 15m = 900_000ms. Create entry 16 minutes old.
        let entry = make_cache_entry("k", 16 * 60 * 1000);
        write_test_cache(dir.path(), &entry);

        match check_cache(dir.path(), "k") {
            CacheStatus::Stale(e) => assert_eq!(e.metadata.cache_key, "k"),
            other => panic!("expected Stale, got {:?}", status_name(&other)),
        }
    }

    #[test]
    fn check_cache_expired_after_hard_ttl() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        // Default hard TTL is 4h = 14_400_000ms. Create entry 5 hours old.
        let entry = make_cache_entry("k", 5 * 60 * 60 * 1000);
        write_test_cache(dir.path(), &entry);

        assert!(matches!(check_cache(dir.path(), "k"), CacheStatus::Expired));
    }

    #[test]
    fn check_cache_corrupt_file_treated_as_missing() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let path = cache_path(dir.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "this is not valid toml {{{{").unwrap();

        assert!(matches!(
            check_cache(dir.path(), "any"),
            CacheStatus::Missing
        ));
    }

    // -----------------------------------------------------------------------
    // invalidate_cache
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_cache_removes_file() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("k", 0);
        write_test_cache(dir.path(), &entry);

        let path = cache_path(dir.path());
        assert!(path.exists());

        invalidate_cache(dir.path());
        assert!(!path.exists());
    }

    #[test]
    fn invalidate_cache_noop_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        // Should not panic or error
        invalidate_cache(dir.path());
    }

    #[test]
    fn invalidate_then_check_returns_missing() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("k", 0);
        write_test_cache(dir.path(), &entry);

        invalidate_cache(dir.path());
        assert!(matches!(check_cache(dir.path(), "k"), CacheStatus::Missing));
    }

    // -----------------------------------------------------------------------
    // write_cache_entry: file permissions
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn cache_file_permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;

        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("k", 0);
        write_test_cache(dir.path(), &entry);

        let path = cache_path(dir.path());
        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn cache_dir_permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;

        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("k", 0);
        write_test_cache(dir.path(), &entry);

        let cache_directory = cache_dir();
        let perms = fs::metadata(&cache_directory).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);
    }

    // -----------------------------------------------------------------------
    // write_cache_entry: atomicity (no partial writes)
    // -----------------------------------------------------------------------

    #[test]
    fn write_cache_does_not_leave_tmp_file() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("k", 0);
        write_test_cache(dir.path(), &entry);

        let tmp_path = cache_path(dir.path()).with_extension("toml.tmp");
        assert!(
            !tmp_path.exists(),
            "temp file should be cleaned up after rename"
        );
    }

    // -----------------------------------------------------------------------
    // compute_cache_key
    // -----------------------------------------------------------------------

    #[test]
    fn cache_key_changes_with_profile() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let k1 = compute_cache_key(dir.path(), "default");
        let k2 = compute_cache_key(dir.path(), "production");
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_deterministic() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let k1 = compute_cache_key(dir.path(), "default");
        let k2 = compute_cache_key(dir.path(), "default");
        assert_eq!(k1, k2);
    }

    #[test]
    fn cache_key_changes_when_config_file_appears() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let k1 = compute_cache_key(dir.path(), "default");

        // Create a config file
        fs::write(dir.path().join("fnox.toml"), "[secrets]\n").unwrap();
        let k2 = compute_cache_key(dir.path(), "default");
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_changes_when_config_file_modified() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("fnox.toml");
        fs::write(&config_path, "[secrets]\n").unwrap();
        let k1 = compute_cache_key(dir.path(), "default");

        // Wait a bit to ensure mtime differs, then modify
        std::thread::sleep(Duration::from_millis(50));
        fs::write(&config_path, "[secrets]\nFOO = \"bar\"\n").unwrap();
        let k2 = compute_cache_key(dir.path(), "default");
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_fixed_length() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let k = compute_cache_key(dir.path(), "default");
        assert_eq!(k.len(), 32);
    }

    // -----------------------------------------------------------------------
    // is_cache_enabled
    // -----------------------------------------------------------------------

    #[test]
    fn is_cache_enabled_auto_with_age_provider() {
        crate::settings::Settings::reset_for_tests();
        let config = config_with_age_provider();
        let result = is_cache_enabled(&config, "default");
        assert_eq!(result, Some("age".to_string()));
    }

    #[test]
    fn is_cache_enabled_auto_without_encryption_provider() {
        crate::settings::Settings::reset_for_tests();
        let config = config_with_plain_provider();
        let result = is_cache_enabled(&config, "default");
        assert_eq!(result, None);
    }

    #[test]
    fn is_cache_enabled_auto_no_providers_at_all() {
        crate::settings::Settings::reset_for_tests();
        let config = Config::new();
        // Config::new() has no providers, so get_default_provider will error.
        // is_cache_enabled should return None, not panic.
        let result = is_cache_enabled(&config, "default");
        assert_eq!(result, None);
    }

    #[test]
    fn is_cache_enabled_config_opt_out() {
        crate::settings::Settings::reset_for_tests();
        let mut config = config_with_age_provider();
        config.cache = Some(false);
        let result = is_cache_enabled(&config, "default");
        assert_eq!(result, None);
    }

    #[test]
    fn is_cache_enabled_config_opt_in_is_not_override() {
        // cache = true in config does NOT force-enable; it just doesn't opt out.
        // The FNOX_CACHE env var / settings control force-enable.
        crate::settings::Settings::reset_for_tests();
        let mut config = config_with_plain_provider();
        config.cache = Some(true);
        // Auto mode still requires encryption provider
        let result = is_cache_enabled(&config, "default");
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // find_encryption_provider
    // -----------------------------------------------------------------------

    #[test]
    fn find_encryption_provider_age() {
        let config = config_with_age_provider();
        assert_eq!(
            find_encryption_provider(&config, "default"),
            Some("age".to_string())
        );
    }

    #[test]
    fn find_encryption_provider_plain_is_none() {
        let config = config_with_plain_provider();
        assert_eq!(find_encryption_provider(&config, "default"), None);
    }

    #[test]
    fn find_encryption_provider_no_default() {
        let config = Config::new();
        assert_eq!(find_encryption_provider(&config, "default"), None);
    }

    #[test]
    fn find_encryption_provider_1password_is_none() {
        let mut config = Config::new();
        config.providers.insert(
            "op".to_string(),
            ProviderConfig::OnePassword {
                vault: Default::default(),
                account: Default::default(),
                token: Default::default(),
                auth_command: None,
            },
        );
        config.set_default_provider(Some("op".to_string()));
        assert_eq!(find_encryption_provider(&config, "default"), None);
    }

    // -----------------------------------------------------------------------
    // find_project_dir_from_cwd
    // -----------------------------------------------------------------------

    #[test]
    fn find_project_dir_with_config_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("fnox.toml"), "").unwrap();
        let result = find_project_dir_from_cwd(dir.path());
        assert_eq!(result, dir.path());
    }

    #[test]
    fn find_project_dir_falls_back_to_cwd() {
        let dir = tempfile::tempdir().unwrap();
        // No config file — should return the dir itself
        let result = find_project_dir_from_cwd(dir.path());
        assert_eq!(result, dir.path());
    }

    #[test]
    fn find_project_dir_finds_parent_config() {
        crate::settings::Settings::reset_for_tests();
        let parent = tempfile::tempdir().unwrap();
        fs::write(parent.path().join("fnox.toml"), "").unwrap();
        let child = parent.path().join("subdir");
        fs::create_dir(&child).unwrap();

        let result = find_project_dir_from_cwd(&child);
        assert_eq!(result, parent.path());
    }

    // -----------------------------------------------------------------------
    // cache_report
    // -----------------------------------------------------------------------

    #[test]
    fn cache_report_disabled_when_no_encryption() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_plain_provider();
        let report = cache_report(&config, "default", dir.path());

        assert!(!report.enabled);
        assert!(report.encryption_provider.is_none());
        assert!(!report.plaintext_warning);
        assert!(report.cache_file.is_none());
    }

    #[test]
    fn cache_report_enabled_with_age() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_age_provider();
        let report = cache_report(&config, "default", dir.path());

        assert!(report.enabled);
        assert_eq!(report.encryption_provider, Some("age".to_string()));
        assert!(!report.plaintext_warning);
    }

    #[test]
    fn cache_report_shows_existing_cache_file() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("k", 0);
        write_test_cache(dir.path(), &entry);

        let config = config_with_age_provider();
        let report = cache_report(&config, "default", dir.path());

        assert!(report.cache_file.is_some());
        assert_eq!(report.num_secrets, 2);
        assert!(report.age_seconds.is_some());
    }

    #[test]
    fn cache_report_no_file_when_cache_not_written() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_age_provider();
        let report = cache_report(&config, "default", dir.path());

        assert!(report.cache_file.is_none());
        assert_eq!(report.num_secrets, 0);
        assert!(report.age_seconds.is_none());
    }

    // -----------------------------------------------------------------------
    // Overwrite and update scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn write_cache_overwrites_previous_entry() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();

        let entry1 = make_cache_entry("key-v1", 0);
        write_test_cache(dir.path(), &entry1);

        let mut secrets2 = IndexMap::new();
        secrets2.insert("NEW_SECRET".to_string(), "new-val".to_string());
        let entry2 = CacheEntry {
            metadata: CacheMetadata {
                cache_key: "key-v2".to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                encryption_provider: "age".to_string(),
                profile: "default".to_string(),
            },
            secrets: secrets2,
        };
        write_test_cache(dir.path(), &entry2);

        match check_cache(dir.path(), "key-v2") {
            CacheStatus::Fresh(e) => {
                assert_eq!(e.secrets.len(), 1);
                assert_eq!(e.secrets["NEW_SECRET"], "new-val");
            }
            other => panic!("expected Fresh, got {:?}", status_name(&other)),
        }

        // Old key no longer matches
        assert!(matches!(
            check_cache(dir.path(), "key-v1"),
            CacheStatus::Expired
        ));
    }

    // -----------------------------------------------------------------------
    // TTL boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn check_cache_fresh_at_one_second_old() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let entry = make_cache_entry("k", 1_000); // 1 second old
        write_test_cache(dir.path(), &entry);

        assert!(matches!(
            check_cache(dir.path(), "k"),
            CacheStatus::Fresh(_)
        ));
    }

    #[test]
    fn check_cache_fresh_just_before_soft_ttl() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        // 14m59s old (soft TTL is 15m)
        let entry = make_cache_entry("k", 14 * 60 * 1000 + 59 * 1000);
        write_test_cache(dir.path(), &entry);

        assert!(matches!(
            check_cache(dir.path(), "k"),
            CacheStatus::Fresh(_)
        ));
    }

    #[test]
    fn check_cache_stale_just_past_soft_ttl() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        // 15m01s old
        let entry = make_cache_entry("k", 15 * 60 * 1000 + 1_000);
        write_test_cache(dir.path(), &entry);

        assert!(matches!(
            check_cache(dir.path(), "k"),
            CacheStatus::Stale(_)
        ));
    }

    #[test]
    fn check_cache_stale_midway_between_soft_and_hard() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        // 2h old (between 15m soft and 4h hard)
        let entry = make_cache_entry("k", 2 * 60 * 60 * 1000);
        write_test_cache(dir.path(), &entry);

        assert!(matches!(
            check_cache(dir.path(), "k"),
            CacheStatus::Stale(_)
        ));
    }

    #[test]
    fn check_cache_stale_just_before_hard_ttl() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        // 3h59m old
        let entry = make_cache_entry("k", 3 * 60 * 60 * 1000 + 59 * 60 * 1000);
        write_test_cache(dir.path(), &entry);

        assert!(matches!(
            check_cache(dir.path(), "k"),
            CacheStatus::Stale(_)
        ));
    }

    #[test]
    fn check_cache_expired_just_past_hard_ttl() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        // 4h01s old
        let entry = make_cache_entry("k", 4 * 60 * 60 * 1000 + 1_000);
        write_test_cache(dir.path(), &entry);

        assert!(matches!(check_cache(dir.path(), "k"), CacheStatus::Expired));
    }

    // -----------------------------------------------------------------------
    // Background refresh lock
    // -----------------------------------------------------------------------

    #[test]
    fn refreshing_lock_prevents_duplicate_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let refreshing = cache_refreshing_path(dir.path());

        // Simulate an in-progress refresh
        fs::create_dir_all(refreshing.parent().unwrap()).unwrap();
        fs::write(&refreshing, "12345").unwrap();

        // spawn_background_refresh should detect the lock and not panic
        spawn_background_refresh(dir.path());

        // Lock file should still exist (not removed by spawn)
        assert!(refreshing.exists());
    }

    #[test]
    fn stale_refreshing_lock_is_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let refreshing = cache_refreshing_path(dir.path());

        fs::create_dir_all(refreshing.parent().unwrap()).unwrap();
        fs::write(&refreshing, "old-pid").unwrap();

        // Backdate the lock file to 3 minutes ago (stale threshold is 2 min)
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(3 * 60);
        filetime::set_file_mtime(&refreshing, filetime::FileTime::from_system_time(old_time))
            .unwrap();

        // spawn_background_refresh should remove the stale lock.
        // (The actual child process may fail since fnox binary might not be the
        // test binary, but the stale lock removal is what we're testing.)
        spawn_background_refresh(dir.path());

        // The function either removed the old lock and created a new one (if
        // the exe exists), or removed it and failed to spawn (leaving it gone).
        // Either way, the OLD content should be gone.
        if refreshing.exists() {
            let content = fs::read_to_string(&refreshing).unwrap();
            assert_ne!(content, "old-pid");
        }
    }

    // -----------------------------------------------------------------------
    // Multiple projects don't interfere
    // -----------------------------------------------------------------------

    #[test]
    fn separate_projects_have_independent_caches() {
        crate::settings::Settings::reset_for_tests();
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let entry_a = make_cache_entry("key-a", 0);
        let mut entry_b = make_cache_entry("key-b", 0);
        entry_b
            .secrets
            .insert("EXTRA".to_string(), "val".to_string());

        write_test_cache(dir_a.path(), &entry_a);
        write_test_cache(dir_b.path(), &entry_b);

        // Each project sees its own cache
        match check_cache(dir_a.path(), "key-a") {
            CacheStatus::Fresh(e) => assert_eq!(e.secrets.len(), 2),
            other => panic!("expected Fresh for A, got {:?}", status_name(&other)),
        }
        match check_cache(dir_b.path(), "key-b") {
            CacheStatus::Fresh(e) => assert_eq!(e.secrets.len(), 3),
            other => panic!("expected Fresh for B, got {:?}", status_name(&other)),
        }

        // Invalidating one doesn't affect the other
        invalidate_cache(dir_a.path());
        assert!(matches!(
            check_cache(dir_a.path(), "key-a"),
            CacheStatus::Missing
        ));
        assert!(matches!(
            check_cache(dir_b.path(), "key-b"),
            CacheStatus::Fresh(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Plaintext cache entry (empty encryption_provider)
    // -----------------------------------------------------------------------

    #[test]
    fn plaintext_cache_entry_roundtrip() {
        crate::settings::Settings::reset_for_tests();
        let dir = tempfile::tempdir().unwrap();

        let mut secrets = IndexMap::new();
        secrets.insert("PLAIN_SECRET".to_string(), "hello-world".to_string());
        let entry = CacheEntry {
            metadata: CacheMetadata {
                cache_key: "pt-key".to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                encryption_provider: String::new(),
                profile: "default".to_string(),
            },
            secrets,
        };

        write_test_cache(dir.path(), &entry);

        match check_cache(dir.path(), "pt-key") {
            CacheStatus::Fresh(e) => {
                assert!(e.metadata.encryption_provider.is_empty());
                assert_eq!(e.secrets["PLAIN_SECRET"], "hello-world");
            }
            other => panic!("expected Fresh, got {:?}", status_name(&other)),
        }
    }

    // -----------------------------------------------------------------------
    // Helper for debug output
    // -----------------------------------------------------------------------

    fn status_name(s: &CacheStatus) -> &'static str {
        match s {
            CacheStatus::Fresh(_) => "Fresh",
            CacheStatus::Stale(_) => "Stale",
            CacheStatus::Expired => "Expired",
            CacheStatus::Missing => "Missing",
        }
    }
}
