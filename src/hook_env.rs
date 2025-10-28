use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::SystemTime;

/// Session state that persists between hook-env invocations
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HookEnvSession {
    /// Current working directory when session was created
    pub dir: Option<PathBuf>,
    /// Path to fnox.toml file that was loaded (if any)
    pub config_path: Option<PathBuf>,
    /// Last modification time of fnox.toml (milliseconds since epoch)
    pub config_mtime: Option<u128>,
    /// Secrets that were loaded
    pub loaded_secrets: HashMap<String, String>,
    /// Hash of FNOX_* environment variables for change detection
    pub env_var_hash: String,
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

        Ok(Self {
            dir,
            config_path,
            config_mtime,
            loaded_secrets,
            env_var_hash,
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

/// Check if fnox.toml or fnox.local.toml has been modified since last run
fn has_config_been_modified() -> bool {
    // Use find_config to check for either fnox.toml or fnox.local.toml
    let config_path = find_config();

    // Check if config exists now but didn't before
    if config_path.is_some() && PREV_SESSION.config_path.is_none() {
        return true;
    }

    // Check if config existed before but doesn't now
    if config_path.is_none() && PREV_SESSION.config_path.is_some() {
        return true;
    }

    // Check if config path changed
    if config_path != PREV_SESSION.config_path {
        return true;
    }

    // Check if modification time changed
    if let Some(ref current_path) = config_path
        && let Some(prev_mtime) = PREV_SESSION.config_mtime
        && let Ok(metadata) = std::fs::metadata(current_path)
        && let Ok(modified) = metadata.modified()
        && let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH)
    {
        let current_mtime = duration.as_millis();
        if current_mtime != prev_mtime {
            return true;
        }
    }

    false
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

/// Find fnox.toml or fnox.local.toml in current or parent directories
pub fn find_config() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;

    loop {
        let config_path = current.join("fnox.toml");
        if config_path.exists() {
            return Some(config_path);
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
