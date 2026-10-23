//! Opt-in local access audit log.
//!
//! When enabled, every read that resolves secrets appends one JSON line per
//! secret naming what was read, when, by which command, and through which
//! provider. Values, command lines, and environments are never recorded.
//!
//! The log is a plain file the current user can write: it records honest
//! activity by fnox, not a tamper-proof trail. See `docs/guide/audit.md`.

use crate::config::{AuditConfig, Config, SecretConfig};
use crate::env;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// One line of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// The reading command, such as `exec`, `get`, `hook-env`, `mcp`, or `proxy`.
    pub command: String,
    /// Active profiles.
    pub profile: Vec<String>,
    /// The config file that defines the secret.
    pub config: String,
    /// Secret name. Never its value.
    pub secret: String,
    /// Provider the secret is read through, when it has one.
    pub provider: Option<String>,
    /// Whether the daemon answered from its in-memory cache.
    pub cached: bool,
}

/// The default log location: `audit.log` in the fnox state directory.
pub fn default_path() -> PathBuf {
    env::FNOX_STATE_DIR.join("audit.log")
}

/// Whether auditing is on: `FNOX_AUDIT` wins over `[audit] enabled`.
pub fn is_enabled(config: &Config) -> bool {
    env::audit_override().unwrap_or_else(|| config.audit.as_ref().is_some_and(AuditConfig::enabled))
}

/// Where the log lives: `FNOX_AUDIT_PATH`, then `[audit] path`, then the default.
pub fn log_path(config: &Config) -> PathBuf {
    env::audit_path_override()
        .or_else(|| {
            config
                .audit
                .as_ref()
                .and_then(|a| a.path.as_deref())
                .map(expand_home)
        })
        .unwrap_or_else(default_path)
}

fn expand_home(path: &Path) -> PathBuf {
    match path.strip_prefix("~") {
        Ok(rest) => env::HOME_DIR.join(rest),
        Err(_) => path.to_path_buf(),
    }
}

/// Records that `secrets` were read by `command`, if auditing is enabled.
///
/// `cached` names the secrets the daemon served from memory. Failures are
/// logged and swallowed: auditing must never change whether a read succeeds.
pub fn record_reads(
    config: &Config,
    profile: &[String],
    command: &str,
    config_path: &Path,
    secrets: &IndexMap<String, SecretConfig>,
    cached: &dyn Fn(&str) -> bool,
) {
    if secrets.is_empty() || !is_enabled(config) {
        return;
    }
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let default_provider = config.get_default_provider(profile).ok().flatten();
    let entries: Vec<AuditEntry> = secrets
        .iter()
        .map(|(name, secret)| AuditEntry {
            ts: ts.clone(),
            command: command.to_string(),
            profile: profile.to_vec(),
            config: secret
                .source_path
                .as_deref()
                .or_else(|| config.secret_sources.get(name).map(|p| p.as_path()))
                .unwrap_or(config_path)
                .display()
                .to_string(),
            secret: name.clone(),
            provider: secret_provider(secret, default_provider.as_deref()),
            cached: cached(name),
        })
        .collect();
    if let Err(error) = append(&log_path(config), &entries) {
        tracing::warn!("failed to write audit log: {error}");
    }
}

fn secret_provider(secret: &SecretConfig, default_provider: Option<&str>) -> Option<String> {
    if let Some(sync) = &secret.sync {
        return Some(sync.provider.clone());
    }
    secret.value()?;
    secret.provider().or(default_provider).map(str::to_string)
}

/// Appends `entries` to `path` in a single `write` on an `O_APPEND` handle, so
/// concurrent fnox processes do not interleave lines. New files are `0600`.
pub fn append(path: &Path, entries: &[AuditEntry]) -> std::io::Result<()> {
    let mut buf = String::new();
    for entry in entries {
        buf.push_str(&serde_json::to_string(entry).map_err(std::io::Error::other)?);
        buf.push('\n');
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(buf.as_bytes())
}

/// The last `limit` entries of `path` accepted by `keep`, oldest first.
///
/// Streams the file, so memory stays bounded by `limit` however long the log is.
/// Lines that are not entries are skipped; a missing file is an empty log.
pub fn tail(
    path: &Path,
    limit: usize,
    keep: impl Fn(&AuditEntry) -> bool,
) -> std::io::Result<Vec<AuditEntry>> {
    use std::io::BufRead;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut recent = std::collections::VecDeque::with_capacity(limit.min(1024));
    for line in std::io::BufReader::new(file).lines() {
        let Ok(entry) = serde_json::from_str::<AuditEntry>(&line?) else {
            continue;
        };
        if limit == 0 || !keep(&entry) {
            continue;
        }
        if recent.len() == limit {
            recent.pop_front();
        }
        recent.push_back(entry);
    }
    Ok(recent.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(secret: &str, command: &str) -> AuditEntry {
        AuditEntry {
            ts: "2026-01-01T00:00:00.000Z".into(),
            command: command.into(),
            profile: vec!["default".into()],
            config: "fnox.toml".into(),
            secret: secret.into(),
            provider: Some("age".into()),
            cached: false,
        }
    }

    #[test]
    fn append_writes_one_json_line_per_entry_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/audit.log");
        append(&path, &[entry("A", "get"), entry("B", "exec")]).unwrap();
        append(&path, &[entry("C", "mcp")]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3);
        let read = tail(&path, 100, |_| true).unwrap();
        assert_eq!(
            read.iter().map(|e| e.secret.as_str()).collect::<Vec<_>>(),
            ["A", "B", "C"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn log_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        append(&path, &[entry("A", "get")]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn tail_keeps_the_last_matches_skips_garbage_and_tolerates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        assert!(tail(&path, 5, |_| true).unwrap().is_empty());
        std::fs::write(&path, "not json\n").unwrap();
        append(
            &path,
            &[
                entry("A", "get"),
                entry("B", "exec"),
                entry("C", "get"),
                entry("D", "get"),
            ],
        )
        .unwrap();
        let last = tail(&path, 2, |e| e.command == "get").unwrap();
        assert_eq!(
            last.iter().map(|e| e.secret.as_str()).collect::<Vec<_>>(),
            ["C", "D"]
        );
    }

    #[test]
    fn disabled_by_default_and_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut config = Config::new();
        config.audit = Some(AuditConfig {
            enabled: None,
            path: Some(path.clone()),
        });
        let mut secrets = IndexMap::new();
        secrets.insert("A".to_string(), SecretConfig::default());
        record_reads(
            &config,
            &["default".into()],
            "get",
            Path::new("fnox.toml"),
            &secrets,
            &|_| false,
        );
        assert!(!path.exists());
    }

    #[test]
    fn entries_never_contain_a_value_field() {
        let json = serde_json::to_string(&entry("A", "get")).unwrap();
        let object: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&json).unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "cached", "command", "config", "profile", "provider", "secret", "ts"
            ]
        );
    }
}
