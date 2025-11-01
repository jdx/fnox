use anyhow::Result;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::SystemTime;

/// Session state that persists between hook-env invocations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookEnvSession {
    /// Current working directory when session was created
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// Path to fnox.toml file that was loaded (if any)
    #[serde(default)]
    pub config_path: Option<PathBuf>,
    /// Last modification time of fnox.toml (milliseconds since epoch)
    #[serde(default)]
    pub config_mtime: Option<u128>,
    /// BLAKE3 hashes of secret values (for change detection)
    /// Keys of this map are the secret names (used for deactivation)
    /// Hashed with the session's hash_key to prevent offline dictionary attacks
    /// Uses IndexMap to preserve insertion order
    #[serde(default)]
    pub secret_hashes: IndexMap<String, String>,
    /// Random key used for BLAKE3 keyed hashing (unique per session)
    /// This prevents correlation of hashes across different sessions
    #[serde(default)]
    pub hash_key: [u8; 32],
    /// Hash of FNOX_* environment variables for change detection
    #[serde(default)]
    pub env_var_hash: String,
    /// Hash of all config files in the hierarchy for change detection
    #[serde(default)]
    pub config_files_hash: String,
}

/// Global previous session state, loaded from __FNOX_SESSION env var
pub static PREV_SESSION: LazyLock<HookEnvSession> = LazyLock::new(|| {
    if let Ok(encoded) = std::env::var("__FNOX_SESSION")
        && let Ok(session) = decode_session(&encoded)
    {
        return session;
    }
    HookEnvSession::default()
});

impl HookEnvSession {
    /// Create a new session from current state
    pub fn new(
        dir: Option<PathBuf>,
        config_path: Option<PathBuf>,
        loaded_secrets: HashMap<String, String>,
    ) -> Result<Self> {
        let config_mtime = if let Some(ref path) = config_path {
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_millis())
        } else {
            None
        };

        let env_var_hash = hash_fnox_env_vars();

        // Calculate hash of all config files in the hierarchy
        let config_files_hash = if let Some(ref d) = dir {
            let configs = collect_config_files(d);
            hash_config_files(&configs)
        } else {
            String::new()
        };

        // Generate a random key for this session's hashes
        use blake3::Hasher;
        let hash_key = *Hasher::new()
            .update(b"fnox-session-")
            .update(
                &std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .to_le_bytes(),
            )
            .update(&std::process::id().to_le_bytes())
            .finalize()
            .as_bytes();

        // Compute hashes (not storing plaintext values)
        // Use IndexMap to preserve insertion order
        let secret_hashes: IndexMap<String, String> = loaded_secrets
            .iter()
            .map(|(k, v)| (k.clone(), hash_secret_with_key(&hash_key, k, v)))
            .collect();

        Ok(Self {
            dir,
            config_path,
            config_mtime,
            secret_hashes,
            hash_key,
            env_var_hash,
            config_files_hash,
        })
    }

    /// Serialize session to base64-encoded msgpack
    pub fn encode(&self) -> Result<String> {
        let bytes = rmp_serde::to_vec(self)?;
        let compressed = miniz_oxide::deflate::compress_to_vec(&bytes, 6);
        Ok(data_encoding::BASE64.encode(&compressed))
    }
}

/// Decode session from base64-encoded msgpack
fn decode_session(encoded: &str) -> Result<HookEnvSession> {
    let compressed = data_encoding::BASE64.decode(encoded.as_bytes())?;
    let bytes = miniz_oxide::inflate::decompress_to_vec(&compressed)
        .map_err(|e| anyhow::anyhow!("failed to decompress session: {:?}", e))?;
    let session = rmp_serde::from_slice(&bytes)?;
    Ok(session)
}

/// Compute a BLAKE3 keyed hash of a secret value using a session-specific key
/// We use the secret key name as part of the hash to ensure different secrets
/// with the same value have different hashes (domain separation)
fn hash_secret_with_key(hash_key: &[u8; 32], key: &str, value: &str) -> String {
    let mut hasher = blake3::Hasher::new_keyed(hash_key);
    hasher.update(key.as_bytes());
    hasher.update(b"\x00"); // separator
    hasher.update(value.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Public API for computing hashes with a given session's key
pub fn hash_secret_value_with_session(session: &HookEnvSession, key: &str, value: &str) -> String {
    hash_secret_with_key(&session.hash_key, key, value)
}

/// Check if we should exit early (optimization)
/// Returns true if nothing changed and we can skip work
pub fn should_exit_early() -> bool {
    // Check if directory changed
    if has_directory_changed() {
        tracing::debug!("directory changed, must run hook-env");
        return false;
    }

    // Check if fnox.toml was modified
    if has_config_been_modified() {
        tracing::debug!("fnox.toml modified, must run hook-env");
        return false;
    }

    // Check if FNOX_* env vars changed
    if has_fnox_env_vars_changed() {
        tracing::debug!("FNOX_* env vars changed, must run hook-env");
        return false;
    }

    tracing::debug!("no changes detected, exiting early");
    true
}

/// Check if current directory is different from previous session
fn has_directory_changed() -> bool {
    let current_dir = std::env::current_dir().ok();
    PREV_SESSION.dir != current_dir
}

/// Check if any config files in the hierarchy have been modified since last run
/// This checks all fnox.toml and fnox.local.toml files from current directory up to root
fn has_config_been_modified() -> bool {
    let current_dir = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(_) => return true, // If we can't get current dir, force reload
    };

    // Build a hash of all current config files and their mtimes
    let current_configs = collect_config_files(&current_dir);
    let current_hash = hash_config_files(&current_configs);

    // Compare with the stored hash from the previous session
    if PREV_SESSION.config_files_hash.is_empty() {
        // Old session without config_files_hash - use conservative fallback
        // Without the hash, we can't reliably detect changes, so we must be conservative:
        // - Reload if there was a previous config (might have changed or been deleted)
        // - Reload if there's a current config (might be new or changed)
        // - Only skip if neither previous nor current config exists
        let had_config = PREV_SESSION.config_path.is_some();
        let has_config = !current_configs.is_empty();
        return had_config || has_config;
    }

    // Compare the current hash with the stored hash
    current_hash != PREV_SESSION.config_files_hash
}

/// Collect all config files (fnox.toml, fnox.$FNOX_PROFILE.toml, and fnox.local.toml) from dir up to root
fn collect_config_files(start_dir: &Path) -> Vec<(PathBuf, u128)> {
    use crate::env;
    let mut configs = Vec::new();
    let mut current = start_dir.to_path_buf();

    loop {
        // Check fnox.toml
        let config_path = current.join("fnox.toml");
        if let Ok(metadata) = std::fs::metadata(&config_path)
            && let Ok(modified) = metadata.modified()
            && let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH)
        {
            configs.push((config_path, duration.as_millis()));
        }

        // Check fnox.$FNOX_PROFILE.toml
        if let Some(profile_name) = (*env::FNOX_PROFILE).as_ref()
            && profile_name != "default"
        {
            let profile_config_path = current.join(format!("fnox.{}.toml", profile_name));
            if let Ok(metadata) = std::fs::metadata(&profile_config_path)
                && let Ok(modified) = metadata.modified()
                && let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH)
            {
                configs.push((profile_config_path, duration.as_millis()));
            }
        }

        // Check fnox.local.toml
        let local_config_path = current.join("fnox.local.toml");
        if let Ok(metadata) = std::fs::metadata(&local_config_path)
            && let Ok(modified) = metadata.modified()
            && let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH)
        {
            configs.push((local_config_path, duration.as_millis()));
        }

        // Move to parent directory
        if !current.pop() {
            break;
        }
    }

    configs
}

/// Create a hash of config files and their modification times
fn hash_config_files(configs: &[(PathBuf, u128)]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for (path, mtime) in configs {
        path.hash(&mut hasher);
        mtime.hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

/// Check if FNOX_* environment variables have changed
fn has_fnox_env_vars_changed() -> bool {
    let current_hash = hash_fnox_env_vars();
    current_hash != PREV_SESSION.env_var_hash
}

/// Calculate hash of all FNOX_* environment variables
fn hash_fnox_env_vars() -> String {
    use std::collections::BTreeMap;
    use std::hash::{Hash, Hasher};

    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in std::env::vars() {
        if key.starts_with("FNOX_") {
            vars.insert(key, value);
        }
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    vars.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Find fnox.toml, fnox.$FNOX_PROFILE.toml, or fnox.local.toml in current or parent directories
pub fn find_config() -> Option<PathBuf> {
    use crate::env;
    let mut current = std::env::current_dir().ok()?;

    loop {
        let config_path = current.join("fnox.toml");
        if config_path.exists() {
            return Some(config_path);
        }

        // Check for profile-specific config
        if let Some(profile_name) = (*env::FNOX_PROFILE).as_ref()
            && profile_name != "default"
        {
            let profile_config_path = current.join(format!("fnox.{}.toml", profile_name));
            if profile_config_path.exists() {
                return Some(profile_config_path);
            }
        }

        let local_config_path = current.join("fnox.local.toml");
        if local_config_path.exists() {
            return Some(local_config_path);
        }

        if !current.pop() {
            break;
        }
    }

    None
}
