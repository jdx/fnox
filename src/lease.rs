use crate::config::Config;
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::{self, ProviderCapability};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub cached_credentials: Option<HashMap<String, String>>,
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

/// Determine the project directory from a config file path.
/// Resolves relative paths against the current directory so that running
/// `fnox exec` from different subdirectories of the same project produces
/// the same ledger file (scoped to where the config actually lives).
pub fn project_dir_from_config(config_path: &Path) -> PathBuf {
    // Resolve relative paths against current directory first
    let resolved = if config_path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(config_path))
            .unwrap_or_else(|_| config_path.to_path_buf())
    } else {
        config_path.to_path_buf()
    };
    // Use the parent directory of the resolved config path
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
    /// Path to the lease ledger file, scoped to a project directory
    fn ledger_path(project_dir: &Path) -> PathBuf {
        let hash = hash_project_dir(project_dir);
        env::FNOX_CONFIG_DIR
            .join("leases")
            .join(format!("{hash}.toml"))
    }

    /// Load the lease ledger from disk, creating an empty one if it doesn't exist.
    /// The ledger is scoped to the project directory (parent of the config file).
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
        // Compact: drop entries that are revoked or expired more than 24h ago
        let cutoff = Utc::now() - chrono::Duration::hours(24);
        let mut compacted = self.clone();
        compacted.leases.retain(|r| {
            if r.revoked {
                // Keep revoked records only if they expired recently (for audit visibility)
                return r.expires_at.is_none_or(|exp| exp > cutoff);
            }
            // Keep non-revoked records unless they expired more than 24h ago
            r.expires_at.is_none_or(|exp| exp > cutoff)
        });
        let content = toml_edit::ser::to_string_pretty(&compacted)
            .map_err(|e| FnoxError::ConfigSerializeError { source: e })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, content.as_bytes()))
                .map_err(|e| FnoxError::ConfigWriteFailed {
                    path: path.clone(),
                    source: e,
                })?;
        }
        #[cfg(not(unix))]
        fs::write(&path, content).map_err(|e| FnoxError::ConfigWriteFailed {
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
                    && r.config_hash.as_deref() == Some(config_hash)
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

/// Find an encryption provider if one is configured (default_provider with Encryption capability)
pub async fn find_encryption_provider(
    config: &Config,
    profile: &str,
) -> Option<(String, Box<dyn providers::Provider>)> {
    let provider_name = match config.get_default_provider(profile) {
        Ok(Some(name)) => name,
        _ => return None,
    };

    let providers_map = config.get_providers(profile);
    let provider_config = providers_map.get(&provider_name)?;

    let provider =
        match providers::get_provider_resolved(config, profile, &provider_name, provider_config)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "Could not instantiate encryption provider '{}': {}",
                    provider_name,
                    e
                );
                return None;
            }
        };

    if provider
        .capabilities()
        .contains(&ProviderCapability::Encryption)
    {
        Some((provider_name, provider))
    } else {
        None
    }
}

/// Encrypt credential values using an encryption provider
pub async fn encrypt_credentials(
    provider: &dyn providers::Provider,
    credentials: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut encrypted = HashMap::new();
    for (key, value) in credentials {
        let enc = provider.encrypt(value).await?;
        encrypted.insert(key.clone(), enc);
    }
    Ok(encrypted)
}

/// Decrypt cached credential values using an encryption provider
pub async fn decrypt_credentials(
    provider: &dyn providers::Provider,
    cached: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut decrypted = HashMap::new();
    for (key, value) in cached {
        let dec = provider.get_secret(value).await?;
        decrypted.insert(key.clone(), dec);
    }
    Ok(decrypted)
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
