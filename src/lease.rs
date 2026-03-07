use crate::env;
use crate::error::{FnoxError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Default lease duration when none is specified
pub const DEFAULT_LEASE_DURATION: &str = "15m";

/// A record of an issued lease, stored in the lease ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub lease_id: String,
    pub backend_name: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// The lease ledger, tracking all issued leases
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeaseLedger {
    #[serde(default)]
    pub leases: Vec<LeaseRecord>,
}

impl LeaseLedger {
    /// Path to the lease ledger file
    fn ledger_path() -> PathBuf {
        env::FNOX_CONFIG_DIR.join("leases.toml")
    }

    /// Load the lease ledger from disk, creating an empty one if it doesn't exist
    pub fn load() -> Result<Self> {
        let path = Self::ledger_path();
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

    /// Save the lease ledger to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::ledger_path();
        // Ensure config directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| FnoxError::CreateDirFailed {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let content = toml_edit::ser::to_string_pretty(self)
            .map_err(|e| FnoxError::ConfigSerializeError { source: e })?;
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

    /// Mark a lease as revoked by ID
    pub fn mark_revoked(&mut self, lease_id: &str) -> bool {
        for record in &mut self.leases {
            if record.lease_id == lease_id {
                record.revoked = true;
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
