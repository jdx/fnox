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
    /// Set on entries for requests served or refused by `fnox proxy run`.
    /// Those entries leave `secret` empty and name what was injected here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<AuditRequest>,
}

/// A request the credential proxy served or refused. Never holds headers,
/// bodies, query strings, or values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRequest {
    pub method: String,
    /// Destination host, or the stripped target of a refused request.
    pub domain: String,
    pub path: String,
    /// Secrets (or `lease:<name>`) injected into the request.
    #[serde(default)]
    pub injected: Vec<String>,
    /// Why the proxy turned the request away. `None` for a served request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
}

/// The log entry for one proxy request.
pub fn request_entry(profile: &[String], request: AuditRequest) -> AuditEntry {
    AuditEntry {
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        command: "proxy".to_string(),
        profile: profile.to_vec(),
        config: String::new(),
        secret: String::new(),
        provider: None,
        cached: false,
        request: Some(request),
    }
}

/// Records one proxy request. Failures are logged and swallowed, like
/// [`record_reads`]. This writes on the calling thread; async callers should
/// queue entries for a writer thread instead (see [`AuditWriter`]).
pub fn record_request(path: &Path, profile: &[String], request: AuditRequest) {
    if let Err(error) = append(path, &[request_entry(profile, request)]) {
        tracing::warn!("failed to write audit log: {error}");
    }
}

/// Queue to a thread that appends entries to the log, so slow storage never
/// stalls the caller. Entries are written in order. When the queue (1024
/// entries) is full, new entries are dropped rather than blocking; call
/// [`flush`] before the process exits to wait for what is still queued.
///
/// [`flush`]: AuditWriter::flush
#[derive(Debug)]
pub struct AuditWriter {
    queue: std::sync::mpsc::SyncSender<WriterMessage>,
    /// Set by [`AuditWriter::close`]; held while queuing so no entry can slip in after it
    closed: std::sync::Mutex<bool>,
}

#[derive(Debug)]
enum WriterMessage {
    Entry(Box<AuditEntry>),
    Flush(std::sync::mpsc::SyncSender<bool>),
}

impl AuditWriter {
    /// Starts the writer thread. It ends when the writer is dropped.
    pub fn spawn(path: PathBuf) -> Self {
        let (queue, rx) = std::sync::mpsc::sync_channel::<WriterMessage>(1024);
        let started = std::thread::Builder::new()
            .name("fnox-audit".into())
            .spawn(move || {
                let mut batch: Vec<AuditEntry> = Vec::new();
                // Whether a write failed since the last flush acknowledgment
                let mut failed = false;
                let write = |batch: &mut Vec<AuditEntry>, failed: &mut bool| {
                    if batch.is_empty() {
                        return;
                    }
                    if let Err(error) = append(&path, batch) {
                        tracing::warn!("failed to write audit log: {error}");
                        *failed = true;
                    }
                    batch.clear();
                };
                while let Ok(message) = rx.recv() {
                    let mut pending = vec![message];
                    pending.extend(rx.try_iter().take(255));
                    for message in pending {
                        match message {
                            WriterMessage::Entry(entry) => batch.push(*entry),
                            WriterMessage::Flush(done) => {
                                write(&mut batch, &mut failed);
                                let _ = done.send(!std::mem::take(&mut failed));
                            }
                        }
                    }
                    write(&mut batch, &mut failed);
                }
            });
        if let Err(error) = started {
            tracing::warn!("failed to start audit writer: {error}");
        }
        Self {
            queue,
            closed: std::sync::Mutex::new(false),
        }
    }

    /// Queues one entry without blocking. When the queue is full because the
    /// log's storage has stalled, the entry is dropped, with a warning the first
    /// time, rather than stalling the caller.
    ///
    /// Returns `false` when the writer was closed, so the caller can report the
    /// entry another way. A full queue still returns `true`: the drop is warned about.
    pub fn send(&self, entry: AuditEntry) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WARNED: AtomicBool = AtomicBool::new(false);
        let closed = self.closed.lock().unwrap_or_else(|e| e.into_inner());
        if *closed {
            return false;
        }
        if let Err(std::sync::mpsc::TrySendError::Full(_)) =
            self.queue.try_send(WriterMessage::Entry(Box::new(entry)))
            && !WARNED.swap(true, Ordering::Relaxed)
        {
            tracing::warn!("audit log is not keeping up; dropping request records");
        }
        true
    }

    /// Stops accepting entries, then waits like [`flush`](AuditWriter::flush).
    /// Every entry accepted before the call is covered by the wait; later ones
    /// are refused by [`send`](AuditWriter::send) instead of queued where a
    /// process exit would discard them.
    pub fn close(&self, timeout: std::time::Duration) -> bool {
        *self.closed.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.flush(timeout)
    }

    /// Waits up to `timeout` for every entry queued so far to be written.
    /// Returns `false` when it gave up, for example because the log sits on
    /// stalled storage, or when a write since the last flush failed; entries
    /// may then be lost.
    pub fn flush(&self, timeout: std::time::Duration) -> bool {
        use std::sync::mpsc::TrySendError;
        let deadline = std::time::Instant::now() + timeout;
        let (done, wait) = std::sync::mpsc::sync_channel(1);
        let mut message = WriterMessage::Flush(done);
        loop {
            match self.queue.try_send(message) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(returned)) => {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    message = returned;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
        wait.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .unwrap_or(false)
    }
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
            request: None,
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
            request: None,
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
    fn request_entries_round_trip_and_old_lines_still_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        record_request(
            &path,
            &["default".into()],
            AuditRequest {
                method: "GET".into(),
                domain: "api.example.com".into(),
                path: "/v1".into(),
                injected: vec!["TOKEN".into()],
                refused: None,
            },
        );
        let old = r#"{"ts":"t","command":"get","profile":[],"config":"c","secret":"A","provider":null,"cached":false}"#;
        let mut text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("refused"));
        text.push_str(old);
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        let read = tail(&path, 10, |_| true).unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].request.as_ref().unwrap().injected, ["TOKEN"]);
        assert!(read[1].request.is_none());
    }

    #[test]
    fn closed_writer_refuses_entries_but_keeps_earlier_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let writer = AuditWriter::spawn(path.clone());
        let entry = || {
            request_entry(
                &["default".into()],
                AuditRequest {
                    method: "GET".into(),
                    domain: "api.example.com".into(),
                    path: "/".into(),
                    injected: Vec::new(),
                    refused: None,
                },
            )
        };
        assert!(writer.send(entry()));
        assert!(writer.close(std::time::Duration::from_secs(5)));
        // A handler that outlives shutdown cannot queue a record the exit would lose
        assert!(!writer.send(entry()));
        assert_eq!(tail(&path, 10, |_| true).unwrap().len(), 1);
    }

    #[test]
    fn flush_reports_write_failures() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the log file should be makes every append fail
        let path = dir.path().join("audit.log");
        std::fs::create_dir(&path).unwrap();
        let writer = AuditWriter::spawn(path);
        writer.send(entry("A", "get"));
        assert!(!writer.flush(std::time::Duration::from_secs(5)));
        // The failure is reported once, then the writer is clean again
        assert!(writer.flush(std::time::Duration::from_secs(5)));
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
