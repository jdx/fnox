//! The read-only daemon client.

use crate::document::{ENV_SCHEMA, EnvDocument, EnvScope, KeyRejection};
use crate::path::{RuntimeEnv, SocketKey};
use crate::wire::{CallOptions, Request, ResolveEnvRequest, Response};
use crate::{CallError, WIRE_VERSION, daemon_env_override, platform_supported};
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// A read-only connection recipe for one daemon.
///
/// It never starts the daemon, never stores values in it, and never makes it
/// call a provider. Every call blocks on std I/O; async callers use
/// `spawn_blocking`.
#[derive(Clone, Debug)]
pub struct Client {
    socket_path: PathBuf,
    key: SocketKey,
    timeout: Duration,
}

/// What a daemon told [`Client::hello`] about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloInfo {
    pub protocol: u32,
    pub min_protocol: u32,
    pub fnox_version: String,
    pub pid: u32,
}

/// A request for the environment of one command.
#[derive(Clone, Debug)]
pub struct EnvRequest<'a> {
    /// Where the CLI fallback would run: the config root.
    pub cwd: &'a Path,
    /// The config path as the CLI would get it. `fnox.toml` means discovery.
    pub config: &'a Path,
    pub scope: EnvScope,
    /// `None` is every key in scope. `Some(&[])` is no keys at all, which
    /// differs from `fnox env --json --keys ""`.
    pub keys: Option<&'a [String]>,
    /// Exactly the environment given to the CLI fallback, and never resolved
    /// values. The daemon keys its cache on parts of it.
    pub env: &'a [(String, String)],
}

/// The result of [`Client::resolve_env`].
#[derive(Debug)]
#[non_exhaustive]
pub enum EnvOutcome {
    /// Every requested key was cached.
    Hit(EnvDocument),
    /// These keys are not cached, or need a lease. Run `fnox env --json`.
    Miss { keys: Vec<String> },
    /// The requested keys cannot be provided. The CLI would fail the same way.
    Rejected(KeyRejection),
    /// The project's fnox config, or `FNOX_DAEMON` in the request's
    /// environment, does not enable the daemon.
    Disabled,
    /// No daemon is running for this key, or the platform has none.
    Absent,
    /// The daemon speaks another protocol. `min` and `max` are its range when
    /// it said so, and `None` when it just hung up.
    VersionMismatch { min: Option<u32>, max: Option<u32> },
    /// Anything else went wrong. Treat it as a miss.
    Unavailable(CallError),
}

impl Client {
    pub fn new(key: SocketKey, rt: &RuntimeEnv) -> Self {
        Self {
            socket_path: key.socket_path(rt),
            key,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The read and write timeout. The default is 5 seconds.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Asks the daemon which protocol it speaks. For diagnostics. Never spawns.
    pub fn hello(&self) -> Result<HelloInfo, CallError> {
        let request = Request::Hello {
            protocol: u32::from(WIRE_VERSION),
        };
        match self.call(&request)? {
            Response::Hello {
                protocol,
                min_protocol,
                fnox_version,
                pid,
            } => Ok(HelloInfo {
                protocol,
                min_protocol,
                fnox_version,
                pid,
            }),
            Response::UnsupportedProtocol { .. } => {
                Err(CallError::Protocol("daemon does not accept this protocol"))
            }
            Response::Error { message } => Err(CallError::Daemon(message)),
            _ => Err(CallError::Protocol("unexpected reply to hello")),
        }
    }

    /// One `resolve_env` round trip.
    ///
    /// Never spawns the daemon, never sends `StoreResolved`, and never makes
    /// the daemon call a provider.
    pub fn resolve_env(&self, req: &EnvRequest<'_>) -> EnvOutcome {
        if !platform_supported() {
            return EnvOutcome::Absent;
        }
        let get = |name: &str| {
            req.env
                .iter()
                .rev()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        if daemon_env_override(&get) == Some(false) {
            return EnvOutcome::Disabled;
        }

        let request = Request::ResolveEnv(ResolveEnvRequest {
            protocol: u32::from(WIRE_VERSION),
            cwd: req.cwd.to_path_buf(),
            config: req.config.to_path_buf(),
            profile: self.key.profile().to_vec(),
            age_key_file: self.key.age_key_file().map(Path::to_path_buf),
            if_missing: self.key.if_missing().map(String::from),
            no_defaults: self.key.no_defaults(),
            scope: req.scope,
            keys: req.keys.map(<[String]>::to_vec),
            env: req.env.to_vec(),
        });
        match self.call(&request) {
            Ok(Response::Env { document }) => match validate(&document, req) {
                Ok(()) => EnvOutcome::Hit(document),
                Err(e) => EnvOutcome::Unavailable(e),
            },
            Ok(Response::EnvMiss { keys }) => EnvOutcome::Miss { keys },
            Ok(Response::EnvRejected(rejection)) => EnvOutcome::Rejected(rejection),
            Ok(Response::Disabled) => EnvOutcome::Disabled,
            Ok(Response::UnsupportedProtocol { min, max }) => EnvOutcome::VersionMismatch {
                min: Some(min),
                max: Some(max),
            },
            Ok(Response::Error { message }) => EnvOutcome::Unavailable(CallError::Daemon(message)),
            Ok(_) => {
                EnvOutcome::Unavailable(CallError::Protocol("unexpected reply to resolve_env"))
            }
            Err(e) if e.is_socket_missing() => EnvOutcome::Absent,
            Err(CallError::EmptyResponse) => EnvOutcome::VersionMismatch {
                min: None,
                max: None,
            },
            Err(e) => EnvOutcome::Unavailable(e),
        }
    }

    fn call(&self, request: &Request) -> Result<Response, CallError> {
        crate::wire::call(
            &self.socket_path,
            request,
            &CallOptions::with_timeout(self.timeout),
        )
    }
}

/// A reply that does not answer the request is a protocol violation, not a hit.
fn validate(document: &EnvDocument, req: &EnvRequest<'_>) -> Result<(), CallError> {
    if document.schema != ENV_SCHEMA {
        return Err(CallError::Protocol("unsupported env document schema"));
    }
    if document.scope != req.scope {
        return Err(CallError::Protocol("env document has a different scope"));
    }
    if let Some(keys) = req.keys
        && document
            .set
            .keys()
            .chain(document.files.keys())
            .any(|key| !keys.contains(key))
    {
        return Err(CallError::Protocol("env document has an unrequested key"));
    }
    Ok(())
}
