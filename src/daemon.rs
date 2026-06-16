use crate::commands::Cli;
use crate::config::{Config, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secrets_batch;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

const SOCKET_NAME: &str = "fnoxd.sock";
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ResolveContext {
    pub config: PathBuf,
    pub profile: Option<String>,
    pub age_key_file: Option<PathBuf>,
    pub if_missing: Option<String>,
    pub no_defaults: bool,
    pub no_daemon: bool,
}

impl ResolveContext {
    pub fn from_cli(cli: &Cli) -> Self {
        let settings = crate::settings::Settings::try_get().ok();
        Self {
            config: cli.config.clone(),
            profile: cli.profile.clone().or_else(|| {
                settings
                    .as_ref()
                    .map(|settings| settings.profile.clone())
                    .filter(|profile| profile != "default")
            }),
            age_key_file: cli.age_key_file.clone().or_else(|| {
                settings
                    .as_ref()
                    .and_then(|settings| settings.age_key_file.clone())
            }),
            if_missing: cli.if_missing.clone().or_else(|| {
                settings
                    .as_ref()
                    .and_then(|settings| settings.if_missing.clone())
            }),
            no_defaults: cli.no_defaults
                || settings
                    .as_ref()
                    .is_some_and(|settings| settings.no_defaults),
            no_daemon: cli.no_daemon,
        }
    }
}

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
    CiRedact,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Get => "get",
            Self::HookEnv => "hook-env",
            Self::Export => "export",
            Self::ListValues => "list-values",
            Self::Check => "check",
            Self::Tui => "tui",
            Self::Mcp => "mcp",
            Self::CiRedact => "ci-redact",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    ResolveBatch(ResolveBatchRequest),
    ResolveOne(ResolveOneRequest),
    Status,
    Clear,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolveBatchRequest {
    cwd: PathBuf,
    config: PathBuf,
    profile: String,
    age_key_file: Option<PathBuf>,
    if_missing: Option<String>,
    no_defaults: bool,
    purpose: String,
    keys: Vec<String>,
    include_env_false: bool,
    env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolveOneRequest {
    cwd: PathBuf,
    config: PathBuf,
    profile: String,
    age_key_file: Option<PathBuf>,
    if_missing: Option<String>,
    no_defaults: bool,
    purpose: String,
    key: String,
    env: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Resolved {
        values: IndexMap<String, Option<String>>,
    },
    Status {
        pid: u32,
        cached_entries: usize,
    },
    Ok,
    Error {
        message: String,
    },
}

#[derive(Debug)]
enum DaemonCallError {
    SocketUnavailable {
        path: PathBuf,
        source: std::io::Error,
    },
    Other(FnoxError),
}

impl DaemonCallError {
    fn is_socket_missing(&self) -> bool {
        matches!(
            self,
            Self::SocketUnavailable { source, .. }
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                )
        )
    }

    fn into_fnox_error(self) -> FnoxError {
        match self {
            Self::SocketUnavailable { path, source } => FnoxError::Config(format!(
                "Failed to connect to fnox daemon at {}: {source}",
                path.display()
            )),
            Self::Other(error) => error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey(String);

#[derive(Default)]
struct DaemonState {
    cache: HashMap<CacheKey, Option<String>>,
}

pub async fn resolve_batch(
    cli: &Cli,
    config: &Config,
    profile: &str,
    secrets: &IndexMap<String, SecretConfig>,
    purpose: Purpose,
    include_env_false: bool,
) -> Result<IndexMap<String, Option<String>>> {
    resolve_batch_with_context(
        &ResolveContext::from_cli(cli),
        config,
        profile,
        secrets,
        purpose,
        include_env_false,
    )
    .await
}

pub async fn resolve_batch_with_context(
    ctx: &ResolveContext,
    config: &Config,
    profile: &str,
    secrets: &IndexMap<String, SecretConfig>,
    purpose: Purpose,
    include_env_false: bool,
) -> Result<IndexMap<String, Option<String>>> {
    if !should_use_daemon(ctx, config) {
        let secrets = if include_env_false {
            secrets.clone()
        } else {
            secrets
                .iter()
                .filter(|(_, secret)| secret.env)
                .map(|(key, secret)| (key.clone(), secret.clone()))
                .collect()
        };
        return resolve_secrets_batch(config, profile, &secrets).await;
    }

    let keys = secrets.keys().cloned().collect();
    let request = Request::ResolveBatch(ResolveBatchRequest {
        cwd: std::env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {e}")))?,
        config: ctx.config.clone(),
        profile: profile.to_string(),
        age_key_file: ctx.age_key_file.clone(),
        if_missing: ctx.if_missing.clone(),
        no_defaults: ctx.no_defaults,
        purpose: purpose.as_str().to_string(),
        keys,
        include_env_false,
        env: std::env::vars().collect(),
    });

    match call_or_start(ctx, config, request).await? {
        Response::Resolved { values } => Ok(values),
        Response::Error { message } => Err(FnoxError::Config(message)),
        _ => Err(FnoxError::Config(
            "Invalid daemon response for ResolveBatch".to_string(),
        )),
    }
}

pub async fn resolve_one(
    cli: &Cli,
    config: &Config,
    profile: &str,
    key: &str,
    secret_config: &SecretConfig,
    purpose: Purpose,
) -> Result<Option<String>> {
    resolve_one_with_context(
        &ResolveContext::from_cli(cli),
        config,
        profile,
        key,
        secret_config,
        purpose,
    )
    .await
}

pub async fn resolve_one_with_context(
    ctx: &ResolveContext,
    config: &Config,
    profile: &str,
    key: &str,
    secret_config: &SecretConfig,
    purpose: Purpose,
) -> Result<Option<String>> {
    if !should_use_daemon(ctx, config) {
        return crate::secret_resolver::resolve_secret(config, profile, key, secret_config).await;
    }

    let request = Request::ResolveOne(ResolveOneRequest {
        cwd: std::env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {e}")))?,
        config: ctx.config.clone(),
        profile: profile.to_string(),
        age_key_file: ctx.age_key_file.clone(),
        if_missing: ctx.if_missing.clone(),
        no_defaults: ctx.no_defaults,
        purpose: purpose.as_str().to_string(),
        key: key.to_string(),
        env: std::env::vars().collect(),
    });

    match call_or_start(ctx, config, request).await? {
        Response::Resolved { mut values } => Ok(values.swap_remove(key).flatten()),
        Response::Error { message } => Err(FnoxError::Config(message)),
        _ => Err(FnoxError::Config(
            "Invalid daemon response for ResolveOne".to_string(),
        )),
    }
}

pub async fn status(cli: &Cli) -> Result<Option<(u32, usize)>> {
    status_for_context(&ResolveContext::from_cli(cli)).await
}

async fn status_for_context(ctx: &ResolveContext) -> Result<Option<(u32, usize)>> {
    match call(socket_path_for_context(ctx)?, Request::Status).await {
        Ok(Response::Status {
            pid,
            cached_entries,
        }) => Ok(Some((pid, cached_entries))),
        Ok(Response::Error { message }) => Err(FnoxError::Config(message)),
        Ok(_) => Err(FnoxError::Config(
            "Invalid daemon response for Status".to_string(),
        )),
        Err(e) if e.is_socket_missing() => Ok(None),
        Err(e) => Err(e.into_fnox_error()),
    }
}

pub async fn clear(cli: &Cli) -> Result<()> {
    match call(socket_path(cli)?, Request::Clear).await {
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Error { message }) => Err(FnoxError::Config(message)),
        Ok(_) => Err(FnoxError::Config(
            "Invalid daemon response for Clear".to_string(),
        )),
        Err(e) => Err(e.into_fnox_error()),
    }
}

pub async fn shutdown(cli: &Cli) -> Result<()> {
    match call(socket_path(cli)?, Request::Shutdown).await {
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Error { message }) => Err(FnoxError::Config(message)),
        Ok(_) => Err(FnoxError::Config(
            "Invalid daemon response for Shutdown".to_string(),
        )),
        Err(e) if e.is_socket_missing() => Ok(()),
        Err(e) => Err(e.into_fnox_error()),
    }
}

pub async fn start_background(cli: &Cli, config: Option<&Config>) -> Result<bool> {
    start_background_for_context(&ResolveContext::from_cli(cli), config).await
}

async fn start_background_for_context(
    ctx: &ResolveContext,
    config: Option<&Config>,
) -> Result<bool> {
    if status_for_context(ctx).await?.is_some() {
        return Ok(false);
    }

    let exe = std::env::current_exe()
        .map_err(|e| FnoxError::Config(format!("Failed to locate fnox executable: {e}")))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--profile")
        .arg(Config::get_profile(ctx.profile.as_deref()));
    if ctx.no_defaults {
        cmd.arg("--no-defaults");
    }
    if let Some(if_missing) = &ctx.if_missing {
        cmd.arg("--if-missing").arg(if_missing);
    }
    if let Some(age_key_file) = &ctx.age_key_file {
        cmd.arg("--age-key-file").arg(age_key_file);
    }
    cmd.arg("daemon").arg("serve");
    if let Some(config) = config
        && let Some(daemon) = &config.daemon
    {
        cmd.env("FNOX_DAEMON_IDLE_TIMEOUT", daemon.idle_timeout());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: pre_exec runs in the child after fork and before exec. setsid is
        // async-signal-safe and detaches the daemon from the caller's terminal session.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn()
        .map_err(|e| FnoxError::Config(format!("Failed to start fnox daemon: {e}")))?;

    let path = socket_path_for_context(ctx)?;
    for _ in 0..50 {
        if path.exists() && status_for_context(ctx).await?.is_some() {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Err(FnoxError::Config(
        "fnox daemon did not become ready".to_string(),
    ))
}

pub async fn serve(cli: &Cli, idle_timeout: Duration) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = cli;
        let _ = idle_timeout;
        return Err(FnoxError::Config(
            "fnox daemon is currently supported on Unix platforms only".to_string(),
        ));
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd"
        ))
    ))]
    {
        let _ = cli;
        let _ = idle_timeout;
        return Err(FnoxError::Config(
            "fnox daemon peer verification is not supported on this Unix platform".to_string(),
        ));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd"
    ))]
    {
        let path = socket_path(cli)?;
        prepare_socket_path(&path)?;
        if path.exists() {
            match UnixStream::connect(&path).await {
                Ok(_) => {
                    return Err(FnoxError::Config(format!(
                        "fnox daemon is already running at {}",
                        path.display()
                    )));
                }
                Err(_) => {
                    std::fs::remove_file(&path).map_err(|e| {
                        FnoxError::Config(format!(
                            "Failed to remove stale daemon socket {}: {e}",
                            path.display()
                        ))
                    })?;
                }
            }
        }

        let listener = UnixListener::bind(&path).map_err(|e| {
            FnoxError::Config(format!(
                "Failed to bind daemon socket {}: {e}",
                path.display()
            ))
        })?;
        set_socket_permissions(&path)?;

        let state = std::sync::Arc::new(Mutex::new(DaemonState::default()));
        let request_lock = std::sync::Arc::new(Mutex::new(()));
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let mut tasks = JoinSet::new();
        loop {
            let accepted = tokio::select! {
                _ = shutdown_rx.recv() => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(e)) = joined {
                        tracing::warn!("daemon request task failed: {e}");
                    }
                    continue;
                }
                accepted = tokio::time::timeout(idle_timeout, listener.accept()) => accepted,
            };
            let (stream, _) = match accepted {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    tracing::warn!("daemon accept failed: {e}");
                    continue;
                }
                Err(_) => break,
            };
            if let Err(e) = verify_peer(&stream) {
                tracing::warn!("rejected daemon client: {e}");
                continue;
            }

            let state = state.clone();
            let request_lock = request_lock.clone();
            let shutdown_tx = shutdown_tx.clone();
            tasks.spawn(async move {
                if let Err(e) = handle_connection(stream, state, request_lock, shutdown_tx).await {
                    tracing::warn!("daemon request failed: {e}");
                }
            });
        }

        if !tasks.is_empty() {
            let drained = tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, async {
                while let Some(result) = tasks.join_next().await {
                    if let Err(e) = result {
                        tracing::warn!("daemon request task failed: {e}");
                    }
                }
            })
            .await;
            if drained.is_err() {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }
        }

        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        Ok(())
    }
}

fn should_use_daemon(ctx: &ResolveContext, config: &Config) -> bool {
    #[cfg(not(unix))]
    {
        let _ = ctx;
        let _ = config;
        return false;
    }

    if !daemon_supported() {
        return false;
    }
    if ctx.no_daemon {
        return false;
    }
    match std::env::var("FNOX_DAEMON").ok().as_deref() {
        Some("0" | "false" | "off" | "no") => return false,
        Some("1" | "true" | "on" | "yes") => return true,
        _ => {}
    }
    config.daemon.as_ref().is_some_and(|d| d.enabled())
}

fn daemon_supported() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd"
    ))
}

async fn call_or_start(
    ctx: &ResolveContext,
    config: &Config,
    request: Request,
) -> Result<Response> {
    #[cfg(not(unix))]
    {
        let _ = ctx;
        let _ = config;
        let _ = request;
        return Err(FnoxError::Config(
            "fnox daemon is currently supported on Unix platforms only".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        let path = socket_path_for_context(ctx)?;
        match call(path.clone(), request.clone()).await {
            Ok(response) => Ok(response),
            Err(e) if e.is_socket_missing() => {
                start_background_for_context(ctx, Some(config)).await?;
                call(path, request)
                    .await
                    .map_err(DaemonCallError::into_fnox_error)
            }
            Err(e) => Err(e.into_fnox_error()),
        }
    }
}

#[cfg(unix)]
async fn call(path: PathBuf, request: Request) -> std::result::Result<Response, DaemonCallError> {
    let mut stream =
        UnixStream::connect(&path)
            .await
            .map_err(|source| DaemonCallError::SocketUnavailable {
                path: path.clone(),
                source,
            })?;
    verify_peer(&stream).map_err(DaemonCallError::Other)?;
    let line = serde_json::to_string(&request).map_err(|e| {
        DaemonCallError::Other(FnoxError::Config(format!(
            "Failed to encode daemon request: {e}"
        )))
    })?;
    stream.write_all(line.as_bytes()).await.map_err(|e| {
        DaemonCallError::Other(FnoxError::Config(format!(
            "Failed to write daemon request: {e}"
        )))
    })?;
    stream.write_all(b"\n").await.map_err(|e| {
        DaemonCallError::Other(FnoxError::Config(format!(
            "Failed to write daemon request: {e}"
        )))
    })?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).await.map_err(|e| {
        DaemonCallError::Other(FnoxError::Config(format!(
            "Failed to read daemon response: {e}"
        )))
    })?;
    serde_json::from_str(&response).map_err(|e| {
        DaemonCallError::Other(FnoxError::Config(format!(
            "Failed to decode daemon response: {e}"
        )))
    })
}

#[cfg(not(unix))]
async fn call(_path: PathBuf, _request: Request) -> std::result::Result<Response, DaemonCallError> {
    Err(DaemonCallError::Other(FnoxError::Config(
        "fnox daemon is currently supported on Unix platforms only".to_string(),
    )))
}

async fn handle_connection(
    stream: UnixStream,
    state: std::sync::Arc<Mutex<DaemonState>>,
    request_lock: std::sync::Arc<Mutex<()>>,
    shutdown_tx: tokio::sync::mpsc::UnboundedSender<()>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| FnoxError::Config(format!("Failed to read daemon request: {e}")))?;
    let request: Request = serde_json::from_str(&line)
        .map_err(|e| FnoxError::Config(format!("Failed to decode daemon request: {e}")))?;

    let shutdown = matches!(request, Request::Shutdown);
    let response = match process_request(request, state, request_lock).await {
        Ok(response) => response,
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    };
    let mut stream = reader.into_inner();
    let response_line = serde_json::to_string(&response)
        .map_err(|e| FnoxError::Config(format!("Failed to encode daemon response: {e}")))?;
    stream
        .write_all(response_line.as_bytes())
        .await
        .map_err(|e| FnoxError::Config(format!("Failed to write daemon response: {e}")))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|e| FnoxError::Config(format!("Failed to write daemon response: {e}")))?;
    if shutdown {
        let _ = shutdown_tx.send(());
    }
    Ok(())
}

async fn process_request(
    request: Request,
    state: std::sync::Arc<Mutex<DaemonState>>,
    request_lock: std::sync::Arc<Mutex<()>>,
) -> Result<Response> {
    match request {
        Request::Status => {
            let state = state.lock().await;
            Ok(Response::Status {
                pid: std::process::id(),
                cached_entries: state.cache.len(),
            })
        }
        Request::Clear => {
            let _guard = request_lock.lock().await;
            state.lock().await.cache.clear();
            Ok(Response::Ok)
        }
        Request::Shutdown => {
            let _guard = request_lock.lock().await;
            Ok(Response::Ok)
        }
        Request::ResolveBatch(req) => {
            let _guard = request_lock.lock().await;
            let _env = EnvOverlay::apply(&req.env)?;
            let _cwd = CwdGuard::change_to(&req.cwd)?;
            apply_request_settings(
                req.age_key_file.clone(),
                Some(req.profile.clone()),
                req.if_missing.clone(),
                req.no_defaults,
            );
            let config = Config::load_smart(&req.config)?;
            let all_secrets = config.get_secrets(&req.profile)?;
            let requested = req.keys.iter().cloned().collect::<HashSet<_>>();
            let secrets: IndexMap<String, SecretConfig> = all_secrets
                .into_iter()
                .filter(|(key, sc)| requested.contains(key) && (req.include_env_false || sc.env))
                .collect();
            let values = resolve_with_cache(&config, &req.profile, secrets, &req, state).await?;
            Ok(Response::Resolved { values })
        }
        Request::ResolveOne(req) => {
            let _guard = request_lock.lock().await;
            let _env = EnvOverlay::apply(&req.env)?;
            let _cwd = CwdGuard::change_to(&req.cwd)?;
            apply_request_settings(
                req.age_key_file.clone(),
                Some(req.profile.clone()),
                req.if_missing.clone(),
                req.no_defaults,
            );
            let config = Config::load_smart(&req.config)?;
            let Some(secret_config) = config.get_secret(&req.profile, &req.key).cloned() else {
                return Ok(Response::Resolved {
                    values: [(req.key, None)].into_iter().collect(),
                });
            };
            let batch_req = ResolveBatchRequest {
                cwd: req.cwd,
                config: req.config,
                profile: req.profile,
                age_key_file: req.age_key_file,
                if_missing: req.if_missing,
                no_defaults: req.no_defaults,
                purpose: req.purpose,
                keys: vec![req.key.clone()],
                include_env_false: true,
                env: req.env,
            };
            let values = resolve_with_cache(
                &config,
                &batch_req.profile,
                [(req.key, secret_config)].into_iter().collect(),
                &batch_req,
                state,
            )
            .await?;
            Ok(Response::Resolved { values })
        }
    }
}

fn apply_request_settings(
    age_key_file: Option<PathBuf>,
    profile: Option<String>,
    if_missing: Option<String>,
    no_defaults: bool,
) {
    crate::settings::Settings::set_cli_snapshot(crate::settings::CliSnapshot {
        age_key_file,
        profile,
        if_missing,
        no_defaults,
    });
}

async fn resolve_with_cache(
    config: &Config,
    profile: &str,
    secrets: IndexMap<String, SecretConfig>,
    req: &ResolveBatchRequest,
    state: std::sync::Arc<Mutex<DaemonState>>,
) -> Result<IndexMap<String, Option<String>>> {
    let fingerprint = config_fingerprint(config, &req.env)?;
    let providers = config.get_providers(profile);
    let mut results = IndexMap::new();
    let mut misses = IndexMap::new();
    let mut miss_keys = HashMap::new();

    {
        let state = state.lock().await;
        for (key, secret) in &secrets {
            let cacheable = req.purpose != Purpose::Check.as_str()
                && secret.daemon_cache.unwrap_or(true)
                && secret
                    .provider()
                    .and_then(|p| providers.get(p))
                    .is_none_or(|p| p.daemon_cache_enabled());
            if cacheable {
                let cache_key = cache_key(&fingerprint, profile, key, secret, req);
                if let Some(value) = state.cache.get(&cache_key) {
                    results.insert(key.clone(), value.clone());
                    continue;
                }
                miss_keys.insert(key.clone(), cache_key);
            }
            misses.insert(key.clone(), secret.clone());
        }
    }

    if !misses.is_empty() {
        let resolved = resolve_secrets_batch(config, profile, &misses).await?;
        let mut state = state.lock().await;
        for (key, value) in resolved {
            if let Some(cache_key) = miss_keys.remove(&key) {
                state.cache.insert(cache_key, value.clone());
            }
            results.insert(key, value);
        }
    }

    let mut ordered = IndexMap::new();
    for key in secrets.keys() {
        if let Some(value) = results.swap_remove(key) {
            ordered.insert(key.clone(), value);
        }
    }
    Ok(ordered)
}

fn cache_key(
    fingerprint: &str,
    profile: &str,
    key: &str,
    secret: &SecretConfig,
    req: &ResolveBatchRequest,
) -> CacheKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(fingerprint.as_bytes());
    hasher.update(profile.as_bytes());
    hasher.update(req.no_defaults.to_string().as_bytes());
    hasher.update(key.as_bytes());
    hasher.update(req.purpose.as_bytes());
    hasher.update(serde_json::to_string(secret).unwrap_or_default().as_bytes());
    CacheKey(hasher.finalize().to_hex().to_string())
}

fn config_fingerprint(config: &Config, env: &[(String, String)]) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut paths = HashSet::new();
    for path in config.provider_sources.values() {
        paths.insert(path.clone());
    }
    for path in config.secret_sources.values() {
        paths.insert(path.clone());
    }
    if let Some(path) = &config.default_provider_source {
        paths.insert(path.clone());
    }
    if let Some(project_dir) = &config.project_dir {
        for name in crate::config::all_config_filenames(None) {
            let path = project_dir.join(name);
            if path.exists() {
                paths.insert(path);
            }
        }
    }
    let mut paths: Vec<_> = paths.into_iter().collect();
    paths.sort();
    for path in paths {
        hasher.update(path.to_string_lossy().as_bytes());
        if let Ok(content) = std::fs::read(&path) {
            hasher.update(&content);
        }
    }
    let mut env = env.to_vec();
    env.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in env {
        if key.starts_with("FNOX_") || provider_env_key(&key) {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn provider_env_key(key: &str) -> bool {
    matches!(
        key,
        "AWS_ACCESS_KEY_ID"
            | "AWS_SECRET_ACCESS_KEY"
            | "AWS_SESSION_TOKEN"
            | "AWS_PROFILE"
            | "AWS_REGION"
            | "AWS_DEFAULT_REGION"
            | "OP_SERVICE_ACCOUNT_TOKEN"
            | "BW_SESSION"
            | "BWS_ACCESS_TOKEN"
            | "VAULT_TOKEN"
            | "VAULT_ADDR"
            | "GOOGLE_APPLICATION_CREDENTIALS"
            | "AZURE_CLIENT_ID"
            | "AZURE_CLIENT_SECRET"
            | "AZURE_TENANT_ID"
            | "INFISICAL_TOKEN"
            | "KEEPASS_PASSWORD"
            | "PASSWORDSTATE_API_KEY"
    )
}

fn socket_path(cli: &Cli) -> Result<PathBuf> {
    socket_path_for_context(&ResolveContext::from_cli(cli))
}

fn socket_path_for_context(ctx: &ResolveContext) -> Result<PathBuf> {
    let mut hasher = blake3::Hasher::new();
    let profile = Config::get_profile(ctx.profile.as_deref());
    hasher.update(profile.as_bytes());
    hasher.update(ctx.no_defaults.to_string().as_bytes());
    if let Some(if_missing) = &ctx.if_missing {
        hasher.update(if_missing.as_bytes());
    }
    if let Some(age_key_file) = &ctx.age_key_file {
        hasher.update(age_key_file.to_string_lossy().as_bytes());
    }
    Ok(runtime_dir()?.join(format!(
        "{}-{}",
        &hasher.finalize().to_hex()[..16],
        SOCKET_NAME
    )))
}

fn runtime_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("fnox-{}", current_uid())));
    let dir = base.join("fnox");
    if socket_path_fits(&dir) {
        return Ok(dir);
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(base.to_string_lossy().as_bytes());
    let digest = hasher.finalize().to_hex();
    let short_base = PathBuf::from("/tmp")
        .join(format!("fnox-{}", current_uid()))
        .join(&digest[..8]);
    let dir = short_base.join("fnox");
    Ok(dir)
}

fn socket_path_fits(dir: &Path) -> bool {
    let socket_name_len = 16 + 1 + SOCKET_NAME.len();
    dir.to_string_lossy().len() + 1 + socket_name_len < 100
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(FnoxError::Config("Invalid daemon socket path".to_string()));
    };
    std::fs::create_dir_all(parent)
        .map_err(|e| FnoxError::Config(format!("Failed to create daemon runtime dir: {e}")))?;
    #[cfg(unix)]
    {
        let temp_user_dir = std::env::temp_dir().join(format!("fnox-{}", current_uid()));
        if parent.starts_with(&temp_user_dir) {
            secure_runtime_component(&temp_user_dir)?;
            if let Some(hash_dir) = parent.parent() {
                secure_runtime_component(hash_dir)?;
            }
        }
        secure_runtime_component(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn secure_runtime_component(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::metadata(path).map_err(|e| {
        FnoxError::Config(format!(
            "Failed to inspect daemon runtime dir {}: {e}",
            path.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(FnoxError::Config(format!(
            "Daemon runtime path {} is not a directory",
            path.display()
        )));
    }
    if metadata.uid() != current_uid() {
        return Err(FnoxError::Config(format!(
            "Daemon runtime dir {} is not owned by the current user",
            path.display()
        )));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        FnoxError::Config(format!(
            "Failed to secure daemon runtime dir {}: {e}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn set_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        FnoxError::Config(format!(
            "Failed to secure daemon socket {}: {e}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn verify_peer(stream: &UnixStream) -> Result<()> {
    let fd = stream.as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(FnoxError::Config(format!(
                "Failed to verify daemon peer credentials: {}",
                std::io::Error::last_os_error()
            )));
        }
        if cred.uid != current_uid() {
            return Err(FnoxError::Config(
                "Daemon client is not owned by the current user".to_string(),
            ));
        }
        return Ok(());
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut euid, &mut egid) };
        if rc != 0 {
            return Err(FnoxError::Config(format!(
                "Failed to verify daemon peer credentials: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _ = egid;
        if euid != current_uid() {
            return Err(FnoxError::Config(
                "Daemon client is not owned by the current user".to_string(),
            ));
        }
        return Ok(());
    }
    #[allow(unreachable_code)]
    Err(FnoxError::Config(
        "fnox daemon peer verification is not supported on this Unix platform".to_string(),
    ))
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

struct EnvOverlay {
    previous: Vec<(String, Option<String>)>,
}

impl EnvOverlay {
    fn apply(env: &[(String, String)]) -> Result<Self> {
        let incoming = env
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<HashSet<_>>();
        let mut touched = env
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<HashSet<_>>();
        for (key, _) in std::env::vars() {
            if !incoming.contains(key.as_str()) {
                touched.insert(key);
            }
        }
        let previous = touched
            .iter()
            .map(|key| (key.clone(), std::env::var(key).ok()))
            .collect::<Vec<_>>();
        for key in touched {
            if !incoming.contains(key.as_str()) {
                crate::env::remove_var(key);
            }
        }
        for (key, value) in env {
            crate::env::set_var(key, value);
        }
        Ok(Self { previous })
    }
}

impl Drop for EnvOverlay {
    fn drop(&mut self) {
        for (key, value) in self.previous.drain(..).rev() {
            match value {
                Some(value) => crate::env::set_var(key, value),
                None => crate::env::remove_var(key),
            }
        }
    }
}

struct CwdGuard {
    previous: PathBuf,
}

impl CwdGuard {
    fn change_to(path: &Path) -> Result<Self> {
        let previous = std::env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {e}")))?;
        std::env::set_current_dir(path).map_err(|e| {
            FnoxError::Config(format!(
                "Failed to switch daemon request cwd to {}: {e}",
                path.display()
            ))
        })?;
        Ok(Self { previous })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.previous);
    }
}

pub fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return Err(FnoxError::Config("duration must not be empty".to_string()));
    }

    let mut total_secs = 0_u64;
    let mut current_num = String::new();
    for c in value.chars() {
        if c.is_ascii_digit() {
            current_num.push(c);
            continue;
        }
        let amount = current_num
            .parse::<u64>()
            .map_err(|_| FnoxError::Config(format!("Invalid duration: {value}")))?;
        current_num.clear();
        let multiplier = match c {
            's' => 1,
            'm' => 60,
            'h' => 60 * 60,
            'd' => 60 * 60 * 24,
            _ => {
                return Err(FnoxError::Config(format!(
                    "Invalid duration unit '{c}' in '{value}'. Use s, m, h, or d"
                )));
            }
        };
        let seconds = amount
            .checked_mul(multiplier)
            .ok_or_else(|| FnoxError::Config(format!("Duration is too large: {value}")))?;
        total_secs = total_secs
            .checked_add(seconds)
            .ok_or_else(|| FnoxError::Config(format!("Duration is too large: {value}")))?;
    }

    if !current_num.is_empty() {
        let seconds = current_num
            .parse::<u64>()
            .map_err(|_| FnoxError::Config(format!("Invalid duration: {value}")))?;
        total_secs = total_secs
            .checked_add(seconds)
            .ok_or_else(|| FnoxError::Config(format!("Duration is too large: {value}")))?;
    }

    if total_secs == 0 {
        return Err(FnoxError::Config(
            "Duration must be greater than 0".to_string(),
        ));
    }
    Ok(Duration::from_secs(total_secs))
}

#[cfg(test)]
mod tests {
    use super::parse_duration;

    #[test]
    fn parse_duration_accepts_combined_values() {
        assert_eq!(parse_duration("2h30m").unwrap().as_secs(), 9000);
        assert_eq!(parse_duration("1d2h3m4s").unwrap().as_secs(), 93784);
    }

    #[test]
    fn parse_duration_rejects_zero_and_overflow() {
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("18446744073709551615d").is_err());
    }
}
