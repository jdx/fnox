//! The daemon's wire protocol, version 6: newline-delimited JSON, one request
//! per connection.
//!
//! This module is shared between the fnox daemon and [`Client`](crate::Client)
//! and is not part of the crate's semver surface. It changes along with
//! [`WIRE_VERSION`](crate::WIRE_VERSION).
//!
//! `Debug` for every request and response is written by hand: environments
//! print as `<N vars>` and secret values are omitted.

use crate::document::{EnvDocument, EnvScope, KeyRejection};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use crate::error::CallError;

/// The longest line, without its newline, either side reads.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Why a secret is being resolved. Part of the cache key, so a value cached
/// for one purpose is not served for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Exec,
    Get,
    HookEnv,
    Export,
    ListValues,
    Check,
    Tui,
    Mcp,
    Proxy,
    CiRedact,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Get => "get",
            Self::HookEnv => "hook-env",
            Self::Export => "export",
            Self::ListValues => "list-values",
            Self::Check => "check",
            Self::Tui => "tui",
            Self::Mcp => "mcp",
            Self::Proxy => "proxy",
            Self::CiRedact => "ci-redact",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    ResolveBatch(ResolveBatchRequest),
    ResolveOne(ResolveOneRequest),
    StoreResolved(StoreResolvedRequest),
    Status,
    Clear,
    /// Evict only these secret keys. A separate variant so a daemon from an
    /// older fnox rejects it instead of reading it as a full `Clear`.
    ClearKeys {
        keys: Vec<String>,
    },
    Shutdown,
    /// Version handshake. Takes no lock and loads no config.
    Hello {
        protocol: u32,
    },
    /// Read cached values for `fnox env --json`. Never calls a provider.
    ResolveEnv(ResolveEnvRequest),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResolveBatchRequest {
    pub cwd: PathBuf,
    pub config: PathBuf,
    pub profile: Vec<String>,
    pub age_key_file: Option<PathBuf>,
    pub if_missing: Option<String>,
    pub no_defaults: bool,
    pub non_interactive: bool,
    pub purpose: String,
    pub keys: Vec<String>,
    /// When true, resolve secrets of every env mode. When false, the resolve
    /// layer keeps only shell-injectable secrets (`env = true`), dropping
    /// `env = "exec"` and `env = false`; callers that pre-filter pass true.
    ///
    /// The wire key stays `include_env_false` for cross-version daemon
    /// compatibility (a stale daemon must still deserialize new requests).
    #[serde(rename = "include_env_false")]
    pub include_all_modes: bool,
    pub env: Vec<(String, String)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResolveOneRequest {
    pub cwd: PathBuf,
    pub config: PathBuf,
    pub profile: Vec<String>,
    pub age_key_file: Option<PathBuf>,
    pub if_missing: Option<String>,
    pub no_defaults: bool,
    pub non_interactive: bool,
    pub purpose: String,
    pub key: String,
    pub env: Vec<(String, String)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoreResolvedRequest {
    pub request: ResolveBatchRequest,
    pub fingerprint: String,
    pub values: IndexMap<String, Option<String>>,
    /// Clear epoch the daemon reported when it handed resolution to the client.
    /// Values for keys cleared since then are stale and not cached. Absent from
    /// older clients, which skip the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

/// A cache-only read of the environment for `scope`. There is no
/// `non_interactive` and no `purpose`: the purpose is derived from the scope.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolveEnvRequest {
    pub protocol: u32,
    pub cwd: PathBuf,
    pub config: PathBuf,
    pub profile: Vec<String>,
    pub age_key_file: Option<PathBuf>,
    pub if_missing: Option<String>,
    pub no_defaults: bool,
    pub scope: EnvScope,
    /// `None` is every key in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    pub env: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Resolved {
        values: IndexMap<String, Option<String>>,
    },
    ResolveInForeground {
        fingerprint: String,
        cached_values: IndexMap<String, Option<String>>,
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
    },
    Status {
        pid: u32,
        cached_entries: usize,
    },
    Ok,
    Error {
        message: String,
    },
    Hello {
        protocol: u32,
        min_protocol: u32,
        fnox_version: String,
        pid: u32,
    },
    /// Every requested key was cached.
    Env {
        document: EnvDocument,
    },
    /// Some requested keys are not cached, or need a lease.
    EnvMiss {
        keys: Vec<String>,
    },
    /// The requested keys cannot be provided.
    EnvRejected(KeyRejection),
    /// This project's fnox config does not enable the daemon.
    Disabled,
    UnsupportedProtocol {
        min: u32,
        max: u32,
    },
}

struct Vars<'a>(&'a [(String, String)]);

impl fmt::Debug for Vars<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} vars>", self.0.len())
    }
}

/// Keys with their values left out.
struct KeysOf<'a, V>(&'a IndexMap<String, V>);

impl<V> fmt::Debug for KeysOf<'_, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

impl fmt::Debug for ResolveBatchRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolveBatchRequest")
            .field("cwd", &self.cwd)
            .field("config", &self.config)
            .field("profile", &self.profile)
            .field("age_key_file", &self.age_key_file)
            .field("if_missing", &self.if_missing)
            .field("no_defaults", &self.no_defaults)
            .field("non_interactive", &self.non_interactive)
            .field("purpose", &self.purpose)
            .field("keys", &self.keys)
            .field("include_all_modes", &self.include_all_modes)
            .field("env", &Vars(&self.env))
            .finish()
    }
}

impl fmt::Debug for ResolveOneRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolveOneRequest")
            .field("cwd", &self.cwd)
            .field("config", &self.config)
            .field("profile", &self.profile)
            .field("age_key_file", &self.age_key_file)
            .field("if_missing", &self.if_missing)
            .field("no_defaults", &self.no_defaults)
            .field("non_interactive", &self.non_interactive)
            .field("purpose", &self.purpose)
            .field("key", &self.key)
            .field("env", &Vars(&self.env))
            .finish()
    }
}

impl fmt::Debug for StoreResolvedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreResolvedRequest")
            .field("request", &self.request)
            .field("fingerprint", &self.fingerprint)
            .field("values", &KeysOf(&self.values))
            .field("epoch", &self.epoch)
            .finish()
    }
}

impl fmt::Debug for ResolveEnvRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolveEnvRequest")
            .field("protocol", &self.protocol)
            .field("cwd", &self.cwd)
            .field("config", &self.config)
            .field("profile", &self.profile)
            .field("age_key_file", &self.age_key_file)
            .field("if_missing", &self.if_missing)
            .field("no_defaults", &self.no_defaults)
            .field("scope", &self.scope)
            .field("keys", &self.keys)
            .field("env", &Vars(&self.env))
            .finish()
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResolveBatch(req) => f.debug_tuple("ResolveBatch").field(req).finish(),
            Self::ResolveOne(req) => f.debug_tuple("ResolveOne").field(req).finish(),
            Self::StoreResolved(req) => f.debug_tuple("StoreResolved").field(req).finish(),
            Self::Status => f.write_str("Status"),
            Self::Clear => f.write_str("Clear"),
            Self::ClearKeys { keys } => f.debug_struct("ClearKeys").field("keys", keys).finish(),
            Self::Shutdown => f.write_str("Shutdown"),
            Self::Hello { protocol } => {
                f.debug_struct("Hello").field("protocol", protocol).finish()
            }
            Self::ResolveEnv(req) => f.debug_tuple("ResolveEnv").field(req).finish(),
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved { values } => f
                .debug_struct("Resolved")
                .field("values", &KeysOf(values))
                .finish(),
            Self::ResolveInForeground {
                fingerprint,
                cached_values,
                keys,
                epoch,
            } => f
                .debug_struct("ResolveInForeground")
                .field("fingerprint", fingerprint)
                .field("cached_values", &KeysOf(cached_values))
                .field("keys", keys)
                .field("epoch", epoch)
                .finish(),
            Self::Status {
                pid,
                cached_entries,
            } => f
                .debug_struct("Status")
                .field("pid", pid)
                .field("cached_entries", cached_entries)
                .finish(),
            Self::Ok => f.write_str("Ok"),
            Self::Error { message } => f.debug_struct("Error").field("message", message).finish(),
            Self::Hello {
                protocol,
                min_protocol,
                fnox_version,
                pid,
            } => f
                .debug_struct("Hello")
                .field("protocol", protocol)
                .field("min_protocol", min_protocol)
                .field("fnox_version", fnox_version)
                .field("pid", pid)
                .finish(),
            Self::Env { document } => f.debug_struct("Env").field("document", document).finish(),
            Self::EnvMiss { keys } => f.debug_struct("EnvMiss").field("keys", keys).finish(),
            Self::EnvRejected(rejection) => f.debug_tuple("EnvRejected").field(rejection).finish(),
            Self::Disabled => f.write_str("Disabled"),
            Self::UnsupportedProtocol { min, max } => f
                .debug_struct("UnsupportedProtocol")
                .field("min", min)
                .field("max", max)
                .finish(),
        }
    }
}

/// How [`call`] behaves.
#[derive(Clone, Debug, Default)]
pub struct CallOptions {
    /// Read and write timeout. `None` waits as long as the daemon takes.
    pub timeout: Option<Duration>,
}

impl CallOptions {
    /// Wait as long as the daemon takes, as fnox's own calls do.
    pub fn no_timeout() -> Self {
        Self { timeout: None }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout: Some(timeout),
        }
    }
}

/// Sends `request` to the daemon at `path` and reads its reply.
///
/// Verifies the peer's user id before writing anything.
#[cfg(unix)]
pub fn call(path: &Path, request: &Request, options: &CallOptions) -> Result<Response, CallError> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn io_error(context: &str, e: std::io::Error) -> CallError {
        CallError::Io(std::io::Error::new(e.kind(), format!("{context}: {e}")))
    }

    let mut stream = UnixStream::connect(path).map_err(|source| CallError::SocketUnavailable {
        path: path.to_path_buf(),
        source,
    })?;
    crate::peer::verify_peer(stream.as_raw_fd()).map_err(CallError::PeerRejected)?;
    stream
        .set_read_timeout(options.timeout)
        .and_then(|()| stream.set_write_timeout(options.timeout))
        .map_err(|e| io_error("Failed to configure daemon socket", e))?;

    let mut line = serde_json::to_vec(request).map_err(|e| {
        CallError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to encode daemon request: {e}"),
        ))
    })?;
    if line.len() > MAX_LINE_BYTES {
        return Err(CallError::Oversize);
    }
    line.push(b'\n');
    stream
        .write_all(&line)
        .map_err(|e| io_error("Failed to write daemon request", e))?;

    let mut reader = BufReader::new(&stream).take(MAX_LINE_BYTES as u64 + 1);
    let mut response = Vec::new();
    let read = reader
        .read_until(b'\n', &mut response)
        .map_err(|e| io_error("Failed to read daemon response", e))?;
    if read == 0 {
        return Err(CallError::EmptyResponse);
    }
    if response.last() == Some(&b'\n') {
        response.pop();
    }
    if response.len() > MAX_LINE_BYTES {
        return Err(CallError::Oversize);
    }
    serde_json::from_slice(&response).map_err(CallError::Decode)
}

/// Sends `request` to the daemon at `path` and reads its reply.
#[cfg(not(unix))]
pub fn call(
    _path: &Path,
    _request: &Request,
    _options: &CallOptions,
) -> Result<Response, CallError> {
    Err(CallError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::SecretValue;

    fn batch() -> ResolveBatchRequest {
        ResolveBatchRequest {
            cwd: PathBuf::from("/p"),
            config: PathBuf::from("fnox.toml"),
            profile: vec!["default".to_string()],
            age_key_file: None,
            if_missing: None,
            no_defaults: false,
            non_interactive: true,
            purpose: "get".to_string(),
            keys: vec!["API_KEY".to_string()],
            include_all_modes: true,
            env: vec![("TOKEN".to_string(), "s3cr3t".to_string())],
        }
    }

    fn values() -> IndexMap<String, Option<String>> {
        IndexMap::from([
            ("API_KEY".to_string(), Some("s3cr3t".to_string())),
            ("NONE".to_string(), None),
        ])
    }

    fn round_trip(json: &str) {
        let request: Request = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&request).unwrap(), json);
    }

    fn round_trip_response(json: &str) {
        let response: Response = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&response).unwrap(), json);
    }

    // The `include_all_modes` field serializes as `include_env_false` on the
    // wire so a stale daemon from an older fnox version can still deserialize
    // requests from a newer client (and vice versa) across an upgrade. Guard
    // that key name against accidental churn.
    #[test]
    fn resolve_batch_request_wire_key_is_stable() {
        let json = serde_json::to_string(&batch()).unwrap();
        assert!(
            json.contains("\"include_env_false\":true"),
            "wire key changed, breaking cross-version daemon IPC: {json}"
        );
        assert!(!json.contains("include_all_modes"));

        let decoded: ResolveBatchRequest = serde_json::from_str(&json).unwrap();
        assert!(decoded.include_all_modes);
    }

    // A full clear keeps the wire shape older daemons expect. A keyed clear uses
    // its own type so an older daemon rejects it instead of clearing everything.
    #[test]
    fn clear_request_wire_shape_is_compatible() {
        let full = serde_json::to_string(&Request::Clear).unwrap();
        assert_eq!(full, r#"{"type":"clear"}"#);

        let keyed = serde_json::to_string(&Request::ClearKeys {
            keys: vec!["API_KEY".to_string()],
        })
        .unwrap();
        assert_eq!(keyed, r#"{"type":"clear_keys","keys":["API_KEY"]}"#);
    }

    #[test]
    fn v5_request_shapes_are_byte_identical() {
        round_trip(r#"{"type":"status"}"#);
        round_trip(r#"{"type":"clear"}"#);
        round_trip(r#"{"type":"shutdown"}"#);
        round_trip(r#"{"type":"clear_keys","keys":["A","B"]}"#);
        round_trip(
            r#"{"type":"resolve_batch","cwd":"/p","config":"fnox.toml","profile":["default"],"age_key_file":null,"if_missing":null,"no_defaults":false,"non_interactive":true,"purpose":"get","keys":["API_KEY"],"include_env_false":true,"env":[["TOKEN","s3cr3t"]]}"#,
        );
        round_trip(
            r#"{"type":"resolve_one","cwd":"/p","config":"fnox.toml","profile":["default"],"age_key_file":"/k","if_missing":"warn","no_defaults":true,"non_interactive":false,"purpose":"get","key":"K","env":[]}"#,
        );
        round_trip(
            r#"{"type":"store_resolved","request":{"cwd":"/p","config":"fnox.toml","profile":["default"],"age_key_file":null,"if_missing":null,"no_defaults":false,"non_interactive":true,"purpose":"get","keys":["API_KEY"],"include_env_false":true,"env":[]},"fingerprint":"abc","values":{"API_KEY":"v","NONE":null},"epoch":3}"#,
        );
    }

    #[test]
    fn store_resolved_omits_a_missing_epoch() {
        let request = Request::StoreResolved(StoreResolvedRequest {
            request: batch(),
            fingerprint: "f".to_string(),
            values: values(),
            epoch: None,
        });
        assert!(!serde_json::to_string(&request).unwrap().contains("epoch"));
        // And an older client's request, which has none, still decodes.
        let json = r#"{"type":"store_resolved","request":{"cwd":"/p","config":"c","profile":[],"age_key_file":null,"if_missing":null,"no_defaults":false,"non_interactive":true,"purpose":"get","keys":[],"include_env_false":false,"env":[]},"fingerprint":"f","values":{}}"#;
        let Request::StoreResolved(decoded) = serde_json::from_str(json).unwrap() else {
            panic!("not store_resolved");
        };
        assert_eq!(decoded.epoch, None);
    }

    #[test]
    fn v5_response_shapes_are_byte_identical() {
        round_trip_response(r#"{"status":"resolved","values":{"A":"1","B":null}}"#);
        round_trip_response(r#"{"status":"status","pid":7,"cached_entries":2}"#);
        round_trip_response(r#"{"status":"ok"}"#);
        round_trip_response(r#"{"status":"error","message":"boom"}"#);
        round_trip_response(
            r#"{"status":"resolve_in_foreground","fingerprint":"f","cached_values":{"A":"1"},"keys":["B"],"epoch":4}"#,
        );
        // `epoch` is omitted when absent.
        round_trip_response(
            r#"{"status":"resolve_in_foreground","fingerprint":"f","cached_values":{},"keys":["B"]}"#,
        );
    }

    #[test]
    fn v6_request_shapes() {
        round_trip(r#"{"type":"hello","protocol":6}"#);
        round_trip(
            r#"{"type":"resolve_env","protocol":6,"cwd":"/p","config":"fnox.toml","profile":["default"],"age_key_file":null,"if_missing":null,"no_defaults":false,"scope":"exec","keys":["A","B"],"env":[["HOME","/home/u"],["PATH","/bin"]]}"#,
        );
        // `keys` is optional.
        round_trip(
            r#"{"type":"resolve_env","protocol":6,"cwd":"/p","config":"fnox.toml","profile":["dev","prod"],"age_key_file":"/k","if_missing":"warn","no_defaults":true,"scope":"shell","env":[]}"#,
        );
        let Request::ResolveEnv(decoded) = serde_json::from_str(
            r#"{"type":"resolve_env","protocol":6,"cwd":"/p","config":"c","profile":[],"age_key_file":null,"if_missing":null,"no_defaults":false,"scope":"exec","keys":null,"env":[]}"#,
        )
        .unwrap() else {
            panic!("not resolve_env");
        };
        assert_eq!(decoded.keys, None);
    }

    #[test]
    fn v6_response_shapes() {
        round_trip_response(
            r#"{"status":"hello","protocol":6,"min_protocol":6,"fnox_version":"1.40.0","pid":123}"#,
        );
        round_trip_response(r#"{"status":"env_miss","keys":["B"]}"#);
        round_trip_response(r#"{"status":"disabled"}"#);
        round_trip_response(r#"{"status":"unsupported_protocol","min":6,"max":6}"#);
        round_trip_response(
            r#"{"status":"env_rejected","unknown":["U"],"suggestions":{"U":["V"]},"not_injectable":[{"key":"S","env":false}]}"#,
        );
        round_trip_response(
            r#"{"status":"env","document":{"schema":1,"fnox_version":"1.40.0","scope":"exec","profile":["default"],"set":{"B":"2","A":"1"},"files":{"F":"x"},"remove":["R"],"missing":[],"leases":[]}}"#,
        );
    }

    #[test]
    fn env_rejected_decodes_with_absent_fields() {
        let Response::EnvRejected(rejection) =
            serde_json::from_str(r#"{"status":"env_rejected","unknown":["U"]}"#).unwrap()
        else {
            panic!("not env_rejected");
        };
        assert_eq!(rejection.unknown, ["U"]);
        assert!(rejection.suggestions.is_empty());
        assert!(rejection.not_injectable.is_empty());
    }

    #[test]
    fn env_document_preserves_index_map_order() {
        let json = r#"{"status":"env","document":{"schema":1,"fnox_version":"1","scope":"exec","profile":["default"],"set":{"Z":"1","A":"2","M":"3"},"files":{},"remove":[],"missing":[],"leases":[]}}"#;
        let Response::Env { document } = serde_json::from_str(json).unwrap() else {
            panic!("not env");
        };
        assert_eq!(
            document.set.keys().map(String::as_str).collect::<Vec<_>>(),
            ["Z", "A", "M"]
        );
        assert_eq!(document.set["A"], SecretValue::new("2".to_string()));
    }

    #[test]
    fn debug_never_contains_values() {
        let renderings = [
            format!("{:?}", Request::ResolveBatch(batch())),
            format!(
                "{:?}",
                Request::ResolveOne(ResolveOneRequest {
                    cwd: PathBuf::from("/p"),
                    config: PathBuf::from("c"),
                    profile: Vec::new(),
                    age_key_file: None,
                    if_missing: None,
                    no_defaults: false,
                    non_interactive: true,
                    purpose: "get".to_string(),
                    key: "K".to_string(),
                    env: vec![("TOKEN".to_string(), "s3cr3t".to_string())],
                })
            ),
            format!(
                "{:?}",
                Request::StoreResolved(StoreResolvedRequest {
                    request: batch(),
                    fingerprint: "f".to_string(),
                    values: values(),
                    epoch: None,
                })
            ),
            format!(
                "{:?}",
                Request::ResolveEnv(ResolveEnvRequest {
                    protocol: 6,
                    cwd: PathBuf::from("/p"),
                    config: PathBuf::from("c"),
                    profile: Vec::new(),
                    age_key_file: None,
                    if_missing: None,
                    no_defaults: false,
                    scope: EnvScope::Exec,
                    keys: None,
                    env: vec![("TOKEN".to_string(), "s3cr3t".to_string())],
                })
            ),
            format!("{:?}", Response::Resolved { values: values() }),
            format!(
                "{:?}",
                Response::ResolveInForeground {
                    fingerprint: "f".to_string(),
                    cached_values: values(),
                    keys: Vec::new(),
                    epoch: None,
                }
            ),
        ];
        for debug in &renderings {
            assert!(!debug.contains("s3cr3t"), "{debug}");
        }
        assert!(renderings[0].contains("<1 vars>"));
        assert!(renderings[2].contains("API_KEY"));
    }

    #[test]
    fn purposes_have_stable_names() {
        assert_eq!(Purpose::Exec.as_str(), "exec");
        assert_eq!(Purpose::HookEnv.as_str(), "hook-env");
        assert_eq!(Purpose::Check.as_str(), "check");
    }
}
