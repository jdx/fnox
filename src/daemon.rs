use crate::child_env;
use crate::commands::Cli;
use crate::config::{Config, ProviderConfig, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::secret_resolver::{resolve_secrets_batch, resolve_secrets_batch_with_pre_resolved};
use fnox_client::path::{RuntimeEnv, SocketKey};
pub use fnox_client::wire::Purpose;
use fnox_client::wire::{
    CallError, CallOptions, MAX_LINE_BYTES, Request, ResolveBatchRequest, ResolveEnvRequest,
    ResolveOneRequest, Response, StoreResolvedRequest,
};
use fnox_client::{MIN_PROTOCOL, WIRE_VERSION, daemon_env_override, platform_supported};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
#[cfg(unix)]
use tokio::task::JoinSet;

const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ResolveContext {
    pub config: PathBuf,
    pub profile: Vec<String>,
    pub age_key_file: Option<PathBuf>,
    pub if_missing: Option<String>,
    pub no_defaults: bool,
    pub non_interactive: bool,
    pub no_daemon: bool,
}

impl ResolveContext {
    pub fn from_cli(cli: &Cli) -> Self {
        let settings = crate::settings::Settings::try_get().ok();
        Self::from_cli_and_settings(cli, settings.as_deref())
    }

    /// The context for `cli` and the settings that fill what it left unset.
    fn from_cli_and_settings(cli: &Cli, settings: Option<&crate::settings::SettingsData>) -> Self {
        let profile = if cli.profile.is_empty() {
            Config::normalize_profiles(
                settings
                    .map(|settings| settings.profile.as_slice())
                    .unwrap_or_default(),
            )
        } else {
            Config::normalize_profiles(&cli.profile)
        };
        Self {
            config: cli.config.clone(),
            profile,
            age_key_file: cli
                .age_key_file
                .clone()
                .or_else(|| settings.and_then(|settings| settings.age_key_file.clone())),
            if_missing: cli
                .if_missing
                .clone()
                .or_else(|| settings.and_then(|settings| settings.if_missing.clone())),
            no_defaults: cli.no_defaults || settings.is_some_and(|settings| settings.no_defaults),
            non_interactive: cli.non_interactive || crate::env::is_non_interactive(),
            no_daemon: cli.no_daemon,
        }
    }

    /// Which daemon serves this context.
    pub fn socket_key(&self) -> SocketKey {
        SocketKey::new(
            &self.profile,
            self.no_defaults,
            self.if_missing.clone(),
            self.age_key_file.clone(),
        )
    }
}

/// What a failed call to the daemon says, in fnox's own error type.
fn into_fnox_error(error: CallError) -> FnoxError {
    FnoxError::Config(error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Secret name, kept alongside the hash so entries can be evicted by key.
    secret: String,
    hash: String,
}

#[derive(Default)]
struct DaemonState {
    // Missing values are not cache hits: a provider may recover between requests.
    cache: HashMap<CacheKey, Option<String>>,
    /// Incremented on every clear. A foreground resolution records the epoch it
    /// started at so its write-back can be rejected for keys cleared meanwhile.
    epoch: u64,
    /// Epoch of the last full clear.
    full_clear_epoch: u64,
    /// Epoch of the last keyed clear for each secret name.
    key_clear_epochs: HashMap<String, u64>,
}

impl DaemonState {
    fn clear(&mut self, keys: Vec<String>) {
        self.epoch += 1;
        if keys.is_empty() {
            self.cache.clear();
            self.full_clear_epoch = self.epoch;
            self.key_clear_epochs.clear();
        } else {
            let keys = keys.into_iter().collect::<HashSet<_>>();
            self.cache
                .retain(|cache_key, _| !keys.contains(&cache_key.secret));
            for key in keys {
                self.key_clear_epochs.insert(key, self.epoch);
            }
        }
    }

    /// Whether `key` was cleared after a resolution that started at `epoch`.
    fn cleared_since(&self, key: &str, epoch: u64) -> bool {
        self.full_clear_epoch > epoch
            || self
                .key_clear_epochs
                .get(key)
                .is_some_and(|cleared| *cleared > epoch)
    }
}

pub async fn resolve_batch(
    cli: &Cli,
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    purpose: Purpose,
    include_all_modes: bool,
) -> Result<IndexMap<String, Option<String>>> {
    resolve_batch_with_context(
        &ResolveContext::from_cli(cli),
        config,
        profile,
        secrets,
        purpose,
        include_all_modes,
    )
    .await
}

pub async fn resolve_batch_with_context(
    ctx: &ResolveContext,
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    purpose: Purpose,
    include_all_modes: bool,
) -> Result<IndexMap<String, Option<String>>> {
    if !should_use_daemon(ctx, config) {
        let secrets = if include_all_modes {
            secrets.clone()
        } else {
            secrets
                .iter()
                .filter(|(_, secret)| secret.env_mode().in_shell())
                .map(|(key, secret)| (key.clone(), secret.clone()))
                .collect()
        };
        return resolve_secrets_batch(config, profile, &secrets).await;
    }

    let keys = secrets.keys().cloned().collect();
    let batch_request = ResolveBatchRequest {
        cwd: std::env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {e}")))?,
        config: ctx.config.clone(),
        profile: profile.to_vec(),
        age_key_file: ctx.age_key_file.clone(),
        if_missing: ctx.if_missing.clone(),
        no_defaults: ctx.no_defaults,
        non_interactive: ctx.non_interactive,
        purpose: purpose.as_str().to_string(),
        keys,
        include_all_modes,
        env: std::env::vars().collect(),
    };

    match call_or_start(ctx, config, Request::ResolveBatch(batch_request.clone())).await? {
        Response::Resolved { values } => Ok(values),
        Response::ResolveInForeground {
            fingerprint,
            mut cached_values,
            keys,
            epoch,
        } => {
            let secrets = if include_all_modes {
                secrets.clone()
            } else {
                secrets
                    .iter()
                    .filter(|(_, secret)| secret.env_mode().in_shell())
                    .map(|(key, secret)| (key.clone(), secret.clone()))
                    .collect()
            };
            let foreground_keys = keys.into_iter().collect::<HashSet<_>>();
            let foreground_secrets = secrets
                .iter()
                .filter(|(key, _)| foreground_keys.contains(*key))
                .map(|(key, secret)| (key.clone(), secret.clone()))
                .collect();
            let mut foreground_values = resolve_secrets_batch_with_pre_resolved(
                config,
                profile,
                &foreground_secrets,
                &cached_values,
            )
            .await?;
            let mut values = IndexMap::new();
            for key in secrets.keys() {
                if let Some(value) = cached_values.swap_remove(key) {
                    values.insert(key.clone(), value);
                } else if let Some(value) = foreground_values.swap_remove(key) {
                    values.insert(key.clone(), value);
                }
            }
            if let Err(error) = store_foreground_values(
                ctx,
                config,
                batch_request,
                fingerprint,
                epoch,
                values.clone(),
            )
            .await
            {
                tracing::warn!("failed to fill daemon cache after foreground resolution: {error}");
            }
            Ok(values)
        }
        Response::Error { message } => Err(FnoxError::Config(message)),
        _ => Err(FnoxError::Config(
            "Invalid daemon response for ResolveBatch".to_string(),
        )),
    }
}

pub async fn resolve_one(
    cli: &Cli,
    config: &Config,
    profile: &[String],
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
    profile: &[String],
    key: &str,
    secret_config: &SecretConfig,
    purpose: Purpose,
) -> Result<Option<String>> {
    if !should_use_daemon(ctx, config) {
        return crate::secret_resolver::resolve_secret(config, profile, key, secret_config).await;
    }

    let one_request = ResolveOneRequest {
        cwd: std::env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {e}")))?,
        config: ctx.config.clone(),
        profile: profile.to_vec(),
        age_key_file: ctx.age_key_file.clone(),
        if_missing: ctx.if_missing.clone(),
        no_defaults: ctx.no_defaults,
        non_interactive: ctx.non_interactive,
        purpose: purpose.as_str().to_string(),
        key: key.to_string(),
        env: std::env::vars().collect(),
    };

    match call_or_start(ctx, config, Request::ResolveOne(one_request.clone())).await? {
        Response::Resolved { mut values } => Ok(values.swap_remove(key).flatten()),
        Response::ResolveInForeground {
            fingerprint, epoch, ..
        } => {
            let value =
                crate::secret_resolver::resolve_secret(config, profile, key, secret_config).await?;
            let values = [(key.to_string(), value.clone())].into_iter().collect();
            let batch_request = ResolveBatchRequest {
                cwd: one_request.cwd,
                config: one_request.config,
                profile: one_request.profile,
                age_key_file: one_request.age_key_file,
                if_missing: one_request.if_missing,
                no_defaults: one_request.no_defaults,
                non_interactive: one_request.non_interactive,
                purpose: one_request.purpose,
                keys: vec![key.to_string()],
                include_all_modes: true,
                env: one_request.env,
            };
            if let Err(error) =
                store_foreground_values(ctx, config, batch_request, fingerprint, epoch, values)
                    .await
            {
                tracing::warn!("failed to fill daemon cache after foreground resolution: {error}");
            }
            Ok(value)
        }
        Response::Error { message } => Err(FnoxError::Config(message)),
        _ => Err(FnoxError::Config(
            "Invalid daemon response for ResolveOne".to_string(),
        )),
    }
}

async fn store_foreground_values(
    ctx: &ResolveContext,
    config: &Config,
    request: ResolveBatchRequest,
    fingerprint: String,
    epoch: Option<u64>,
    values: IndexMap<String, Option<String>>,
) -> Result<()> {
    match call_or_start(
        ctx,
        config,
        Request::StoreResolved(StoreResolvedRequest {
            request,
            fingerprint,
            values,
            epoch,
        }),
    )
    .await?
    {
        Response::Ok => Ok(()),
        Response::Error { message } => Err(FnoxError::Config(message)),
        _ => Err(FnoxError::Config(
            "Invalid daemon response for StoreResolved".to_string(),
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
        Err(e) => Err(into_fnox_error(e)),
    }
}

/// Clear the caches of all running daemons. When `keys` is non-empty, only
/// entries for those secret keys are evicted.
pub async fn clear(cli: &Cli, keys: &[String]) -> Result<()> {
    let paths = daemon_socket_paths()?;
    if paths.is_empty() {
        clear_socket(socket_path(cli)?, keys, false).await?;
        return Ok(());
    }

    let mut cleared = false;
    for path in paths {
        cleared |= clear_socket(path, keys, true).await?;
    }

    if !cleared {
        clear_socket(socket_path(cli)?, keys, false).await?;
    }
    Ok(())
}

/// Evict `keys` from the cache of the daemon this invocation would use, so the
/// next resolve fetches them from their providers and caches the new values.
/// Does nothing when the daemon is disabled or not running.
pub async fn refresh(cli: &Cli, config: &Config, keys: &[String]) -> Result<()> {
    let ctx = ResolveContext::from_cli(cli);
    if keys.is_empty() || !should_use_daemon(&ctx, config) {
        return Ok(());
    }
    clear_socket(socket_path_for_context(&ctx)?, keys, true).await?;
    Ok(())
}

/// Returns whether a daemon was listening on `path`.
async fn clear_socket(path: PathBuf, keys: &[String], ignore_missing: bool) -> Result<bool> {
    let request = if keys.is_empty() {
        Request::Clear
    } else {
        Request::ClearKeys {
            keys: keys.to_vec(),
        }
    };
    match call(path.clone(), request).await {
        Ok(Response::Ok) => Ok(true),
        Ok(Response::Error { message }) => Err(FnoxError::Config(message)),
        Ok(_) => Err(FnoxError::Config(
            "Invalid daemon response for Clear".to_string(),
        )),
        Err(e) if ignore_missing && e.is_socket_missing() => Ok(false),
        // A daemon from an older fnox drops the connection on a request it
        // cannot decode. Leave its cache alone rather than failing the clear.
        Err(CallError::EmptyResponse) if ignore_missing && !keys.is_empty() => {
            tracing::warn!(
                "fnox daemon at {} did not accept a keyed clear; it may be from an older fnox. Run `fnox daemon clear` to clear it fully",
                path.display()
            );
            // A daemon was running there, so don't fall back to failing on
            // the current version's (possibly absent) socket.
            Ok(true)
        }
        Err(e) => Err(into_fnox_error(e)),
    }
}

fn daemon_socket_paths() -> Result<Vec<PathBuf>> {
    fnox_client::path::daemon_socket_paths(&RuntimeEnv::from_process())
        .map_err(|e| FnoxError::Config(e.to_string()))
}

pub async fn shutdown(cli: &Cli) -> Result<()> {
    match call(socket_path(cli)?, Request::Shutdown).await {
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Error { message }) => Err(FnoxError::Config(message)),
        Ok(_) => Err(FnoxError::Config(
            "Invalid daemon response for Shutdown".to_string(),
        )),
        Err(e) if e.is_socket_missing() => Ok(()),
        Err(e) => Err(into_fnox_error(e)),
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
    for p in &ctx.profile {
        cmd.arg("--profile").arg(p);
    }
    if ctx.no_defaults {
        cmd.arg("--no-defaults");
    }
    if ctx.non_interactive {
        cmd.arg("--non-interactive");
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
    cmd.current_dir("/");
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
    if !platform_supported() || ctx.no_daemon {
        return false;
    }
    daemon_enabled(config, daemon_env_override(&|k| std::env::var(k).ok()))
}

/// Whether `config` enables the daemon, unless `env_override` (`FNOX_DAEMON`) says.
fn daemon_enabled(config: &Config, env_override: Option<bool>) -> bool {
    env_override.unwrap_or_else(|| config.daemon.as_ref().is_some_and(|d| d.enabled()))
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
                call(path, request).await.map_err(into_fnox_error)
            }
            Err(e) => Err(into_fnox_error(e)),
        }
    }
}

/// Sends `request` to the daemon at `path`. fnox's own calls wait as long as
/// the daemon takes, so the blocking client runs on a blocking thread.
async fn call(path: PathBuf, request: Request) -> std::result::Result<Response, CallError> {
    tokio::task::spawn_blocking(move || {
        fnox_client::wire::call(&path, &request, &CallOptions::no_timeout())
    })
    .await
    .map_err(|e| CallError::Io(std::io::Error::other(format!("daemon call failed: {e}"))))?
}

#[cfg(unix)]
async fn handle_connection(
    stream: UnixStream,
    state: std::sync::Arc<Mutex<DaemonState>>,
    request_lock: std::sync::Arc<Mutex<()>>,
    shutdown_tx: tokio::sync::mpsc::UnboundedSender<()>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    // Read at most one byte more than the limit, so an oversize request is
    // noticed without buffering all of it.
    let mut line = Vec::new();
    (&mut reader)
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|e| FnoxError::Config(format!("Failed to read daemon request: {e}")))?;
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.len() > MAX_LINE_BYTES {
        return Err(FnoxError::Config(format!(
            "Dropped a daemon request over {MAX_LINE_BYTES} bytes"
        )));
    }
    let request: Request = serde_json::from_slice(&line)
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
        Request::Hello { protocol } => {
            if !protocol_supported(protocol) {
                return Ok(unsupported_protocol());
            }
            Ok(Response::Hello {
                protocol: u32::from(WIRE_VERSION),
                min_protocol: MIN_PROTOCOL,
                fnox_version: env!("CARGO_PKG_VERSION").to_string(),
                pid: std::process::id(),
            })
        }
        Request::ResolveEnv(req) => {
            if !protocol_supported(req.protocol) {
                return Ok(unsupported_protocol());
            }
            let _guard = request_lock.lock().await;
            let _env = EnvOverlay::apply(&req.env)?;
            let _cwd = CwdGuard::change_to(&req.cwd)?;
            apply_request_settings(
                req.age_key_file.clone(),
                req.profile.clone(),
                req.if_missing.clone(),
                req.no_defaults,
                false,
            );
            let config = Config::load_smart(&req.config)?;
            // As `fnox env` does, so an unknown profile is an error here and
            // the CLI fallback reports it, rather than an empty hit.
            config.validate_profiles(&req.profile, None)?;
            let env_override = daemon_env_override(&|k| std::env::var(k).ok());
            resolve_env_response(&config, &req, env_override, &state).await
        }
        Request::Status => {
            let state = state.lock().await;
            Ok(Response::Status {
                pid: std::process::id(),
                cached_entries: state.cache.len(),
            })
        }
        Request::Clear => {
            let _guard = request_lock.lock().await;
            state.lock().await.clear(Vec::new());
            Ok(Response::Ok)
        }
        Request::ClearKeys { keys } => {
            let _guard = request_lock.lock().await;
            if !keys.is_empty() {
                state.lock().await.clear(keys);
            }
            Ok(Response::Ok)
        }
        Request::Shutdown => {
            let _guard = request_lock.lock().await;
            Ok(Response::Ok)
        }
        Request::StoreResolved(req) => {
            let _guard = request_lock.lock().await;
            let _env = EnvOverlay::apply(&req.request.env)?;
            let _cwd = CwdGuard::change_to(&req.request.cwd)?;
            apply_request_settings(
                req.request.age_key_file.clone(),
                req.request.profile.clone(),
                req.request.if_missing.clone(),
                req.request.no_defaults,
                req.request.non_interactive,
            );
            let config = Config::load_smart(&req.request.config)?;
            let all_secrets = config.get_secrets(&req.request.profile)?;
            let requested = req.request.keys.iter().cloned().collect::<HashSet<_>>();
            let secrets: IndexMap<String, SecretConfig> = all_secrets
                .into_iter()
                .filter(|(key, sc)| {
                    requested.contains(key)
                        && (req.request.include_all_modes || sc.env_mode().in_shell())
                })
                .collect();
            store_resolved_values(
                &config,
                &req.request.profile,
                &secrets,
                &req.request,
                &req.fingerprint,
                req.epoch,
                req.values,
                state,
            )
            .await?;
            Ok(Response::Ok)
        }
        Request::ResolveBatch(req) => {
            let _guard = request_lock.lock().await;
            let _env = EnvOverlay::apply(&req.env)?;
            let _cwd = CwdGuard::change_to(&req.cwd)?;
            apply_request_settings(
                req.age_key_file.clone(),
                req.profile.clone(),
                req.if_missing.clone(),
                req.no_defaults,
                req.non_interactive,
            );
            let config = Config::load_smart(&req.config)?;
            let all_secrets = config.get_secrets(&req.profile)?;
            let requested = req.keys.iter().cloned().collect::<HashSet<_>>();
            let secrets: IndexMap<String, SecretConfig> = all_secrets
                .into_iter()
                .filter(|(key, sc)| {
                    requested.contains(key) && (req.include_all_modes || sc.env_mode().in_shell())
                })
                .collect();
            if let Some(foreground) =
                foreground_resolution_if_needed(&config, &req.profile, &secrets, &req, &state)
                    .await?
            {
                return Ok(Response::ResolveInForeground {
                    fingerprint: foreground.fingerprint,
                    cached_values: foreground.cached_values,
                    keys: foreground.keys,
                    epoch: Some(foreground.epoch),
                });
            }
            let values = resolve_with_cache(&config, &req.profile, secrets, &req, state).await?;
            Ok(Response::Resolved { values })
        }
        Request::ResolveOne(req) => {
            let _guard = request_lock.lock().await;
            let _env = EnvOverlay::apply(&req.env)?;
            let _cwd = CwdGuard::change_to(&req.cwd)?;
            apply_request_settings(
                req.age_key_file.clone(),
                req.profile.clone(),
                req.if_missing.clone(),
                req.no_defaults,
                req.non_interactive,
            );
            let config = Config::load_smart(&req.config)?;
            let Some(secret_config) = config.get_secret(&req.profile, &req.key)?.cloned() else {
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
                non_interactive: req.non_interactive,
                purpose: req.purpose,
                keys: vec![req.key.clone()],
                include_all_modes: true,
                env: req.env,
            };
            let secrets = [(req.key, secret_config)].into_iter().collect();
            if let Some(foreground) = foreground_resolution_if_needed(
                &config,
                &batch_req.profile,
                &secrets,
                &batch_req,
                &state,
            )
            .await?
            {
                return Ok(Response::ResolveInForeground {
                    fingerprint: foreground.fingerprint,
                    cached_values: foreground.cached_values,
                    keys: foreground.keys,
                    epoch: Some(foreground.epoch),
                });
            }
            let values =
                resolve_with_cache(&config, &batch_req.profile, secrets, &batch_req, state).await?;
            Ok(Response::Resolved { values })
        }
    }
}

fn protocol_supported(protocol: u32) -> bool {
    (MIN_PROTOCOL..=u32::from(WIRE_VERSION)).contains(&protocol)
}

fn unsupported_protocol() -> Response {
    Response::UnsupportedProtocol {
        min: MIN_PROTOCOL,
        max: u32::from(WIRE_VERSION),
    }
}

/// Answers a `resolve_env` request from the cache alone. Never calls a provider.
///
/// - `Disabled` unless the config, or `env_override` (`FNOX_DAEMON`), enables
///   the daemon.
/// - `EnvRejected` for keys that `fnox env` would reject.
/// - `EnvMiss` when a lease is selected (leases never go through the daemon)
///   or any root is not cached. A secret that resolved to nothing is never
///   cached, so it always misses.
/// - Otherwise `Env`, the document `fnox env --json` would print.
async fn resolve_env_response(
    config: &Config,
    req: &ResolveEnvRequest,
    env_override: Option<bool>,
    state: &std::sync::Arc<Mutex<DaemonState>>,
) -> Result<Response> {
    if !daemon_enabled(config, env_override) {
        return Ok(Response::Disabled);
    }
    let secrets = config.get_secrets(&req.profile)?;
    let leases = config.get_leases(&req.profile)?;
    let roots = match &req.keys {
        Some(keys) => child_env::Roots::Keys(keys),
        None => child_env::Roots::Scope,
    };
    let sel = match child_env::select(&secrets, &leases, req.scope, roots) {
        Ok(sel) => sel,
        Err(rejection) => return Ok(Response::EnvRejected(rejection)),
    };
    if !sel.leases.is_empty() {
        let mut keys: Vec<String> = Vec::new();
        match &sel.requested {
            Some(requested) => keys.extend(
                requested
                    .iter()
                    .filter(|key| !sel.roots.contains(key))
                    .cloned(),
            ),
            None => {
                for lease in sel.leases.iter().filter_map(|name| leases.get(name)) {
                    for key in lease.produced_env_vars() {
                        if !keys.iter().any(|existing| existing == key) {
                            keys.push(key.to_string());
                        }
                    }
                }
            }
        }
        return Ok(Response::EnvMiss { keys });
    }

    let purpose = child_env::scope_purpose(req.scope).as_str();
    let fingerprint = config_fingerprint(config, &req.env)?;
    let providers = config.get_providers(&req.profile)?;
    let default_provider = cache_policy_default_provider(config, &req.profile, &providers);
    let mut resolved = IndexMap::new();
    let mut misses = Vec::new();
    {
        let state = state.lock().await;
        for key in &sel.roots {
            let cached = secrets.get(key).and_then(|secret| {
                if !secret_is_cacheable(&providers, default_provider, secret, purpose) {
                    return None;
                }
                let cache_key = cache_key(
                    &fingerprint,
                    &req.profile,
                    key,
                    secret,
                    req.no_defaults,
                    purpose,
                );
                state.cache.get(&cache_key).cloned().flatten()
            });
            match cached {
                Some(value) => {
                    resolved.insert(key.clone(), Some(value));
                }
                None => misses.push(key.clone()),
            }
        }
    }
    if !misses.is_empty() {
        return Ok(Response::EnvMiss { keys: misses });
    }

    let env = child_env::assemble(
        req.scope,
        &secrets,
        &leases,
        &sel,
        &resolved,
        &IndexMap::new(),
        Vec::new(),
    );
    Ok(Response::Env {
        document: child_env::env_document(req.scope, req.profile.clone(), env),
    })
}

fn secret_is_cacheable(
    providers: &IndexMap<String, ProviderConfig>,
    default_provider: Option<&str>,
    secret: &SecretConfig,
    purpose: &str,
) -> bool {
    purpose != Purpose::Check.as_str()
        && secret.daemon_cache.unwrap_or(true)
        && provider_daemon_cache_enabled(providers, default_provider, secret)
}

struct ForegroundResolution {
    fingerprint: String,
    cached_values: IndexMap<String, Option<String>>,
    keys: Vec<String>,
    epoch: u64,
}

async fn foreground_resolution_if_needed(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    req: &ResolveBatchRequest,
    state: &std::sync::Arc<Mutex<DaemonState>>,
) -> Result<Option<ForegroundResolution>> {
    if req.non_interactive || secrets.is_empty() {
        return Ok(None);
    }

    let fingerprint = config_fingerprint(config, &req.env)?;
    let providers = config.get_providers(profile)?;
    let default_provider = cache_policy_default_provider(config, profile, &providers);
    let state = state.lock().await;
    let mut cached_values = IndexMap::new();
    let mut keys = Vec::new();
    for (key, secret) in secrets {
        if secret_is_cacheable(&providers, default_provider, secret, &req.purpose)
            && let Some(Some(value)) = state.cache.get(&cache_key(
                &fingerprint,
                profile,
                key,
                secret,
                req.no_defaults,
                &req.purpose,
            ))
        {
            cached_values.insert(key.clone(), Some(value.clone()));
        } else {
            keys.push(key.clone());
        }
    }
    if keys.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ForegroundResolution {
            fingerprint,
            cached_values,
            keys,
            epoch: state.epoch,
        }))
    }
}

#[allow(clippy::too_many_arguments)]
async fn store_resolved_values(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    req: &ResolveBatchRequest,
    expected_fingerprint: &str,
    epoch: Option<u64>,
    mut values: IndexMap<String, Option<String>>,
    state: std::sync::Arc<Mutex<DaemonState>>,
) -> Result<()> {
    let fingerprint = config_fingerprint(config, &req.env)?;
    if fingerprint != expected_fingerprint {
        tracing::debug!("config changed during foreground resolution; skipping daemon cache fill");
        return Ok(());
    }

    let providers = config.get_providers(profile)?;
    let default_provider = cache_policy_default_provider(config, profile, &providers);
    let mut state = state.lock().await;
    for (key, secret) in secrets {
        if epoch.is_some_and(|epoch| state.cleared_since(key, epoch)) {
            tracing::debug!("{key} was cleared during foreground resolution; not caching it");
            continue;
        }
        if secret_is_cacheable(&providers, default_provider, secret, &req.purpose)
            && let Some(Some(value)) = values.swap_remove(key)
        {
            let cache_key = cache_key(
                &fingerprint,
                profile,
                key,
                secret,
                req.no_defaults,
                &req.purpose,
            );
            state.cache.insert(cache_key, Some(value));
        }
    }
    Ok(())
}

fn apply_request_settings(
    age_key_file: Option<PathBuf>,
    profile: Vec<String>,
    if_missing: Option<String>,
    no_defaults: bool,
    non_interactive: bool,
) {
    crate::settings::Settings::set_cli_snapshot(crate::settings::CliSnapshot {
        age_key_file,
        profile,
        if_missing,
        no_defaults,
    });
    crate::env::set_non_interactive(non_interactive);
}

/// Resolve cache misses while making cached dependency values available to providers.
async fn resolve_with_cache(
    config: &Config,
    profile: &[String],
    secrets: IndexMap<String, SecretConfig>,
    req: &ResolveBatchRequest,
    state: std::sync::Arc<Mutex<DaemonState>>,
) -> Result<IndexMap<String, Option<String>>> {
    let fingerprint = config_fingerprint(config, &req.env)?;
    let providers = config.get_providers(profile)?;
    let default_provider = cache_policy_default_provider(config, profile, &providers);
    let mut results = IndexMap::new();
    let mut misses = IndexMap::new();
    let mut miss_keys = HashMap::new();

    {
        let state = state.lock().await;
        for (key, secret) in &secrets {
            let cacheable = secret_is_cacheable(&providers, default_provider, secret, &req.purpose);
            if cacheable {
                let cache_key = cache_key(
                    &fingerprint,
                    profile,
                    key,
                    secret,
                    req.no_defaults,
                    &req.purpose,
                );
                if let Some(Some(value)) = state.cache.get(&cache_key) {
                    results.insert(key.clone(), Some(value.clone()));
                    continue;
                }
                miss_keys.insert(key.clone(), cache_key);
            }
            misses.insert(key.clone(), secret.clone());
        }
    }

    if !misses.is_empty() {
        let resolved =
            resolve_secrets_batch_with_pre_resolved(config, profile, &misses, &results).await?;
        let mut state = state.lock().await;
        for (key, value) in resolved {
            if let Some(cache_key) = miss_keys.remove(&key)
                && value.is_some()
            {
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

fn cache_policy_default_provider<'a>(
    config: &'a Config,
    profile: &[String],
    providers: &'a IndexMap<String, ProviderConfig>,
) -> Option<&'a str> {
    let profile = config
        .resolve_profiles(profile)
        .unwrap_or_else(|_| profile.to_vec());
    for p in profile.iter().filter(|p| *p != "default").rev() {
        if let Some(profile_config) = config.profiles.get(p)
            && let Some(default_provider) = profile_config.default_provider()
        {
            return Some(default_provider);
        }
    }

    config.default_provider().or_else(|| {
        if providers.len() == 1 {
            providers.keys().next().map(String::as_str)
        } else {
            None
        }
    })
}

fn provider_daemon_cache_enabled(
    providers: &IndexMap<String, ProviderConfig>,
    default_provider: Option<&str>,
    secret: &SecretConfig,
) -> bool {
    let provider_name = if let Some(provider_name) = secret.provider() {
        Some(provider_name)
    } else if secret.value().is_some() {
        default_provider
    } else {
        None
    };

    provider_name
        .and_then(|provider_name| providers.get(provider_name))
        .is_none_or(|provider| provider.daemon_cache_enabled())
}

fn cache_key(
    fingerprint: &str,
    profile: &[String],
    key: &str,
    secret: &SecretConfig,
    no_defaults: bool,
    purpose: &str,
) -> CacheKey {
    let mut hasher = blake3::Hasher::new();
    let profile_str = profile.join(",");
    hasher.update(fingerprint.as_bytes());
    hasher.update(profile_str.as_bytes());
    hasher.update(no_defaults.to_string().as_bytes());
    hasher.update(key.as_bytes());
    hasher.update(purpose.as_bytes());
    hasher.update(serde_json::to_string(secret).unwrap_or_default().as_bytes());
    CacheKey {
        secret: key.to_string(),
        hash: hasher.finalize().to_hex().to_string(),
    }
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
    for profile in config.profiles.values() {
        paths.extend(profile.provider_sources.values().cloned());
        paths.extend(profile.secret_sources.values().cloned());
        if let Some(path) = &profile.default_provider_source {
            paths.insert(path.clone());
        }
    }
    if let Some(project_dir) = &config.project_dir {
        for name in crate::config::all_config_filenames(&[]) {
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
            | "ENPASS_PASSWORD"
            | "INFISICAL_TOKEN"
            | "KEEPASS_PASSWORD"
            | "PASSWORDSTATE_API_KEY"
            | "PROTON_PASS_PASSWORD"
            | "PROTON_PASS_TOTP"
            | "PROTON_PASS_EXTRA_PASSWORD"
            | "PROTON_PASS_PASSWORD_FILE"
            | "PROTON_PASS_TOTP_FILE"
            | "PROTON_PASS_EXTRA_PASSWORD_FILE"
            | "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
            | "PROTON_PASS_AGENT_REASON"
            | "PROTON_PASS_SESSION_DIR"
            | "PROTON_PASS_KEY_PROVIDER"
            | "PROTON_PASS_ENCRYPTION_KEY"
            | "PROTON_PASS_LINUX_KEYRING"
    )
}

fn socket_path(cli: &Cli) -> Result<PathBuf> {
    socket_path_for_context(&ResolveContext::from_cli(cli))
}

fn socket_path_for_context(ctx: &ResolveContext) -> Result<PathBuf> {
    Ok(ctx.socket_key().socket_path(&RuntimeEnv::from_process()))
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(FnoxError::Config("Invalid daemon socket path".to_string()));
    };
    std::fs::create_dir_all(parent)
        .map_err(|e| FnoxError::Config(format!("Failed to create daemon runtime dir: {e}")))?;
    #[cfg(unix)]
    {
        let temp_user_dir = RuntimeEnv::from_process()
            .tmpdir
            .join(format!("fnox-{}", current_uid()));
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
    fnox_client::peer::verify_peer(stream.as_raw_fd()).map_err(|e| FnoxError::Config(e.to_string()))
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        fnox_client::peer::current_euid()
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
    use super::{
        CacheKey, DaemonState, Purpose, Request, ResolveBatchRequest, ResolveContext,
        ResolveEnvRequest, Response, cache_key, config_fingerprint,
        foreground_resolution_if_needed, parse_duration, process_request, resolve_env_response,
        resolve_with_cache, store_resolved_values,
    };
    use fnox_client::document::EnvScope;
    use fnox_core::config::{Config, ProviderConfig, SecretConfig};
    use indexmap::IndexMap;
    use std::{path::PathBuf, sync::Arc};
    use tokio::sync::Mutex;

    #[test]
    fn parse_duration_accepts_combined_values() {
        assert_eq!(parse_duration("2h30m").unwrap().as_secs(), 9000);
        assert_eq!(parse_duration("1d2h3m4s").unwrap().as_secs(), 93784);
    }

    #[tokio::test]
    async fn clear_with_keys_evicts_only_matching_entries() {
        let config = Config::new();
        let secret = plain_secret("value");
        let req = test_batch_request();
        let fingerprint = config_fingerprint(&config, &req.env).unwrap();
        let mut cache = std::collections::HashMap::<CacheKey, Option<String>>::new();
        for key in ["API_KEY", "OTHER_KEY"] {
            cache.insert(
                cache_key(
                    &fingerprint,
                    &req.profile,
                    key,
                    &secret,
                    req.no_defaults,
                    &req.purpose,
                ),
                Some("cached".to_string()),
            );
        }
        let state = Arc::new(Mutex::new(DaemonState {
            cache,
            ..Default::default()
        }));

        let response = process_request(
            Request::ClearKeys {
                keys: vec!["API_KEY".to_string()],
            },
            state.clone(),
            Arc::new(Mutex::new(())),
        )
        .await
        .unwrap();
        assert!(matches!(response, Response::Ok));

        let state = state.lock().await;
        let remaining = state
            .cache
            .keys()
            .map(|key| key.secret.as_str())
            .collect::<Vec<_>>();
        assert_eq!(remaining, vec!["OTHER_KEY"]);
    }

    #[test]
    fn parse_duration_rejects_zero_and_overflow() {
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("18446744073709551615d").is_err());
    }

    #[test]
    fn config_fingerprint_tracks_proton_pass_native_pat() {
        let config = Config::default();
        let first = config_fingerprint(
            &config,
            &[(
                "PROTON_PASS_PERSONAL_ACCESS_TOKEN".to_string(),
                "pst_first".to_string(),
            )],
        )
        .unwrap();
        let second = config_fingerprint(
            &config,
            &[(
                "PROTON_PASS_PERSONAL_ACCESS_TOKEN".to_string(),
                "pst_second".to_string(),
            )],
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn config_fingerprint_tracks_proton_pass_session_env() {
        let config = Config::default();
        let first = config_fingerprint(
            &config,
            &[(
                "PROTON_PASS_SESSION_DIR".to_string(),
                "/tmp/proton-pass-first".to_string(),
            )],
        )
        .unwrap();
        let second = config_fingerprint(
            &config,
            &[(
                "PROTON_PASS_SESSION_DIR".to_string(),
                "/tmp/proton-pass-second".to_string(),
            )],
        )
        .unwrap();

        assert_ne!(first, second);
    }

    fn plain_provider_config(daemon_cache: Option<bool>) -> ProviderConfig {
        ProviderConfig::Plain {
            auth_command: None,
            daemon_cache,
        }
    }

    fn plain_secret(value: &str) -> SecretConfig {
        let mut secret = SecretConfig::new();
        secret.set_provider(Some("plain".to_string()));
        secret.set_value(Some(value.to_string()));
        secret
    }

    fn default_provider_secret(value: &str) -> SecretConfig {
        let mut secret = SecretConfig::new();
        secret.set_value(Some(value.to_string()));
        secret
    }

    fn test_batch_request() -> ResolveBatchRequest {
        ResolveBatchRequest {
            cwd: PathBuf::from("."),
            config: PathBuf::from("fnox.toml"),
            profile: vec!["default".to_string()],
            age_key_file: None,
            if_missing: None,
            no_defaults: false,
            non_interactive: true,
            purpose: Purpose::Get.as_str().to_string(),
            keys: vec!["API_KEY".to_string()],
            include_all_modes: true,
            env: Vec::new(),
        }
    }

    fn state_with_cached_secret(
        config: &Config,
        secret: &SecretConfig,
        req: &ResolveBatchRequest,
    ) -> Arc<Mutex<DaemonState>> {
        let fingerprint = config_fingerprint(config, &req.env).unwrap();
        let key = cache_key(
            &fingerprint,
            &req.profile,
            "API_KEY",
            secret,
            req.no_defaults,
            &req.purpose,
        );
        let mut cache = std::collections::HashMap::<CacheKey, Option<String>>::new();
        cache.insert(key, Some("cached".to_string()));
        Arc::new(Mutex::new(DaemonState {
            cache,
            ..Default::default()
        }))
    }

    #[tokio::test]
    async fn resolve_with_cache_skips_explicit_provider_when_provider_daemon_cache_disabled() {
        let mut config = Config::new();
        config
            .providers
            .insert("plain".to_string(), plain_provider_config(Some(false)));
        let secret = plain_secret("fresh");
        let req = test_batch_request();
        let state = state_with_cached_secret(&config, &secret, &req);

        let resolved = resolve_with_cache(
            &config,
            &req.profile,
            IndexMap::from([("API_KEY".to_string(), secret)]),
            &req,
            state,
        )
        .await
        .unwrap();

        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_deref()),
            Some("fresh")
        );
    }

    // A foreground client that read a value before it was cleared must not
    // write that stale value back afterwards.
    #[tokio::test]
    async fn foreground_write_back_skips_keys_cleared_meanwhile() {
        let mut config = Config::new();
        config
            .providers
            .insert("plain".to_string(), plain_provider_config(None));
        let secrets = IndexMap::from([
            ("API_KEY".to_string(), plain_secret("api")),
            ("OTHER_KEY".to_string(), plain_secret("other")),
        ]);
        let mut req = test_batch_request();
        req.non_interactive = false;
        req.keys = vec!["API_KEY".to_string(), "OTHER_KEY".to_string()];
        let state = Arc::new(Mutex::new(DaemonState::default()));

        let foreground =
            foreground_resolution_if_needed(&config, &req.profile, &secrets, &req, &state)
                .await
                .unwrap()
                .expect("cache misses should be resolved by the foreground client");

        state.lock().await.clear(vec!["API_KEY".to_string()]);

        store_resolved_values(
            &config,
            &req.profile,
            &secrets,
            &req,
            &foreground.fingerprint,
            Some(foreground.epoch),
            IndexMap::from([
                ("API_KEY".to_string(), Some("stale".to_string())),
                ("OTHER_KEY".to_string(), Some("other".to_string())),
            ]),
            state.clone(),
        )
        .await
        .unwrap();

        let state = state.lock().await;
        let cached = state
            .cache
            .keys()
            .map(|key| key.secret.as_str())
            .collect::<Vec<_>>();
        assert_eq!(cached, vec!["OTHER_KEY"]);
    }

    #[tokio::test]
    async fn foreground_client_resolves_cache_miss_and_populates_cache() {
        let mut config = Config::new();
        config
            .providers
            .insert("plain".to_string(), plain_provider_config(None));
        let secret = plain_secret("fresh");
        let secrets = IndexMap::from([("API_KEY".to_string(), secret.clone())]);
        let mut req = test_batch_request();
        req.non_interactive = false;
        let state = Arc::new(Mutex::new(DaemonState::default()));

        let foreground =
            foreground_resolution_if_needed(&config, &req.profile, &secrets, &req, &state)
                .await
                .unwrap()
                .expect("cache miss should be resolved by the foreground client");
        assert_eq!(foreground.keys, ["API_KEY"]);
        assert!(foreground.cached_values.is_empty());

        store_resolved_values(
            &config,
            &req.profile,
            &secrets,
            &req,
            &foreground.fingerprint,
            Some(foreground.epoch),
            IndexMap::from([("API_KEY".to_string(), Some("from-foreground".to_string()))]),
            state.clone(),
        )
        .await
        .unwrap();

        assert!(
            foreground_resolution_if_needed(&config, &req.profile, &secrets, &req, &state,)
                .await
                .unwrap()
                .is_none(),
            "cached requests should stay in the daemon"
        );
        let resolved = resolve_with_cache(&config, &req.profile, secrets, &req, state.clone())
            .await
            .unwrap();
        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_deref()),
            Some("from-foreground")
        );

        let secrets = IndexMap::from([
            ("API_KEY".to_string(), secret),
            ("OTHER_KEY".to_string(), plain_secret("other")),
        ]);
        let foreground =
            foreground_resolution_if_needed(&config, &req.profile, &secrets, &req, &state)
                .await
                .unwrap()
                .expect("the uncached entry should require foreground resolution");
        assert_eq!(foreground.keys, ["OTHER_KEY"]);
        assert_eq!(
            foreground
                .cached_values
                .get("API_KEY")
                .and_then(|value| value.as_deref()),
            Some("from-foreground")
        );
    }

    #[tokio::test]
    async fn non_interactive_client_leaves_cache_miss_for_daemon() {
        let mut config = Config::new();
        config
            .providers
            .insert("plain".to_string(), plain_provider_config(None));
        let secrets = IndexMap::from([("API_KEY".to_string(), plain_secret("fresh"))]);
        let req = test_batch_request();
        let state = Arc::new(Mutex::new(DaemonState::default()));

        assert!(
            foreground_resolution_if_needed(&config, &req.profile, &secrets, &req, &state,)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn resolve_with_cache_skips_default_provider_when_provider_daemon_cache_disabled() {
        let mut config = Config::new();
        config
            .providers
            .insert("plain".to_string(), plain_provider_config(Some(false)));
        config.set_default_provider(Some("plain".to_string()));
        let secret = default_provider_secret("fresh");
        let req = test_batch_request();
        let state = state_with_cached_secret(&config, &secret, &req);

        let resolved = resolve_with_cache(
            &config,
            &req.profile,
            IndexMap::from([("API_KEY".to_string(), secret)]),
            &req,
            state,
        )
        .await
        .unwrap();

        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_deref()),
            Some("fresh")
        );
    }

    #[tokio::test]
    async fn resolve_with_cache_skips_profile_default_provider_when_provider_daemon_cache_disabled()
    {
        let config: Config = toml_edit::de::from_str(
            r#"
root = true

[providers.global]
type = "plain"

[profiles.prod]
default_provider = "plain"

[profiles.prod.providers.plain]
type = "plain"
daemon_cache = false
"#,
        )
        .unwrap();
        let secret = default_provider_secret("fresh");
        let mut req = test_batch_request();
        req.profile = vec!["prod".to_string()];
        let state = state_with_cached_secret(&config, &secret, &req);

        let resolved = resolve_with_cache(
            &config,
            &req.profile,
            IndexMap::from([("API_KEY".to_string(), secret)]),
            &req,
            state,
        )
        .await
        .unwrap();

        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_deref()),
            Some("fresh")
        );
    }

    #[tokio::test]
    async fn resolve_with_cache_skips_auto_selected_provider_when_provider_daemon_cache_disabled() {
        let mut config = Config::new();
        config
            .providers
            .insert("plain".to_string(), plain_provider_config(Some(false)));
        let secret = default_provider_secret("fresh");
        let req = test_batch_request();
        let state = state_with_cached_secret(&config, &secret, &req);

        let resolved = resolve_with_cache(
            &config,
            &req.profile,
            IndexMap::from([("API_KEY".to_string(), secret)]),
            &req,
            state,
        )
        .await
        .unwrap();

        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_deref()),
            Some("fresh")
        );
    }

    #[tokio::test]
    async fn resolve_with_cache_uses_cache_for_default_provider_when_daemon_cache_is_default() {
        let mut config = Config::new();
        config
            .providers
            .insert("plain".to_string(), plain_provider_config(None));
        config.set_default_provider(Some("plain".to_string()));
        let secret = default_provider_secret("fresh");
        let req = test_batch_request();
        let state = state_with_cached_secret(&config, &secret, &req);

        let resolved = resolve_with_cache(
            &config,
            &req.profile,
            IndexMap::from([("API_KEY".to_string(), secret)]),
            &req,
            state,
        )
        .await
        .unwrap();

        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_deref()),
            Some("cached")
        );
    }

    #[tokio::test]
    async fn resolve_with_cache_uses_cache_when_default_provider_config_is_invalid() {
        let mut config = Config::new();
        config
            .providers
            .insert("plain".to_string(), plain_provider_config(None));
        config.set_default_provider(Some("missing".to_string()));
        let secret = default_provider_secret("fresh");
        let req = test_batch_request();
        let state = state_with_cached_secret(&config, &secret, &req);

        let resolved = resolve_with_cache(
            &config,
            &req.profile,
            IndexMap::from([("API_KEY".to_string(), secret)]),
            &req,
            state,
        )
        .await
        .unwrap();

        assert_eq!(
            resolved.get("API_KEY").and_then(|value| value.as_deref()),
            Some("cached")
        );
    }

    // ---- resolve_env ----

    const ENV_CONFIG: &str = r#"
root = true

[daemon]
enabled = true

[providers.plain]
type = "plain"

[secrets]
FOO = { provider = "plain", value = "foo" }
BAR = { provider = "plain", value = "bar", env = "exec" }
HID = { provider = "plain", value = "hid", env = false }
NOCACHE = { provider = "plain", value = "nc", daemon_cache = false }
"#;

    fn env_config(toml: &str) -> Config {
        toml_edit::de::from_str(toml).unwrap()
    }

    fn env_request(scope: EnvScope, keys: Option<&[&str]>) -> ResolveEnvRequest {
        ResolveEnvRequest {
            protocol: 6,
            cwd: PathBuf::from("."),
            config: PathBuf::from("fnox.toml"),
            profile: vec!["default".to_string()],
            age_key_file: None,
            if_missing: None,
            no_defaults: false,
            scope,
            keys: keys.map(|keys| keys.iter().map(|k| k.to_string()).collect()),
            env: Vec::new(),
        }
    }

    /// Seeds the cache the way a foreground resolution does.
    async fn seed(
        config: &Config,
        purpose: &str,
        values: &[(&str, &str)],
    ) -> Arc<Mutex<DaemonState>> {
        let state = Arc::new(Mutex::new(DaemonState::default()));
        seed_into(&state, config, purpose, values).await;
        state
    }

    async fn seed_into(
        state: &Arc<Mutex<DaemonState>>,
        config: &Config,
        purpose: &str,
        values: &[(&str, &str)],
    ) {
        let profile = vec!["default".to_string()];
        let mut req = test_batch_request();
        req.purpose = purpose.to_string();
        req.keys = values.iter().map(|(k, _)| k.to_string()).collect();
        let secrets = config.get_secrets(&profile).unwrap();
        let fingerprint = config_fingerprint(config, &req.env).unwrap();
        store_resolved_values(
            config,
            &profile,
            &secrets,
            &req,
            &fingerprint,
            None,
            values
                .iter()
                .map(|(k, v)| (k.to_string(), Some(v.to_string())))
                .collect(),
            state.clone(),
        )
        .await
        .unwrap();
    }

    async fn respond(
        config: &Config,
        req: &ResolveEnvRequest,
        env_override: Option<bool>,
        state: &Arc<Mutex<DaemonState>>,
    ) -> Response {
        resolve_env_response(config, req, env_override, state)
            .await
            .unwrap()
    }

    fn empty_state() -> Arc<Mutex<DaemonState>> {
        Arc::new(Mutex::new(DaemonState::default()))
    }

    #[tokio::test]
    async fn resolve_env_is_disabled_when_the_config_does_not_enable_the_daemon() {
        let config = env_config("root = true\n[providers.plain]\ntype = \"plain\"\n");
        let req = env_request(EnvScope::Exec, None);
        assert!(matches!(
            respond(&config, &req, None, &empty_state()).await,
            Response::Disabled
        ));
        let config = env_config("root = true\n[daemon]\nenabled = false\n");
        assert!(matches!(
            respond(&config, &req, None, &empty_state()).await,
            Response::Disabled
        ));
    }

    #[tokio::test]
    async fn resolve_env_follows_the_fnox_daemon_override() {
        let req = env_request(EnvScope::Exec, None);
        // `FNOX_DAEMON=off` beats `enabled = true`.
        let enabled = env_config(ENV_CONFIG);
        assert!(matches!(
            respond(&enabled, &req, Some(false), &empty_state()).await,
            Response::Disabled
        ));
        // `FNOX_DAEMON=on` serves a project whose config is silent.
        let silent = env_config(
            "root = true\n[providers.plain]\ntype = \"plain\"\n[secrets]\nFOO = { provider = \"plain\", value = \"foo\" }\n",
        );
        let state = seed(&silent, "exec", &[("FOO", "foo")]).await;
        assert!(matches!(
            respond(&silent, &req, Some(true), &state).await,
            Response::Env { .. }
        ));
    }

    #[tokio::test]
    async fn resolve_env_rejects_unknown_and_env_false_keys() {
        let config = env_config(ENV_CONFIG);
        let req = env_request(EnvScope::Exec, Some(&["FO", "HID"]));
        let Response::EnvRejected(rejection) = respond(&config, &req, None, &empty_state()).await
        else {
            panic!("expected a rejection");
        };
        assert_eq!(rejection.unknown, ["FO"]);
        assert_eq!(rejection.suggestions["FO"], ["FOO"]);
        assert_eq!(rejection.not_injectable.len(), 1);
        assert_eq!(rejection.not_injectable[0].key, "HID");
    }

    #[tokio::test]
    async fn resolve_env_misses_on_an_empty_cache() {
        let config = env_config(ENV_CONFIG);
        let req = env_request(EnvScope::Exec, Some(&["FOO", "BAR"]));
        let Response::EnvMiss { keys } = respond(&config, &req, None, &empty_state()).await else {
            panic!("expected a miss");
        };
        assert_eq!(keys, ["FOO", "BAR"]);
    }

    #[tokio::test]
    async fn resolve_env_hits_after_a_foreground_store() {
        let config = env_config(ENV_CONFIG);
        let state = seed(&config, "exec", &[("FOO", "foo"), ("BAR", "bar")]).await;
        let req = env_request(EnvScope::Exec, Some(&["BAR", "FOO"]));
        let Response::Env { document } = respond(&config, &req, None, &state).await else {
            panic!("expected a hit");
        };
        assert_eq!(document.schema, 1);
        assert_eq!(document.scope, EnvScope::Exec);
        assert_eq!(document.profile, ["default"]);
        // Config order, not request order.
        let set: Vec<_> = document
            .set
            .iter()
            .map(|(k, v)| (k.as_str(), v.expose()))
            .collect();
        assert_eq!(set, [("FOO", "foo"), ("BAR", "bar")]);
        assert!(document.files.is_empty());
        assert!(document.missing.is_empty());
        assert!(document.leases.is_empty());

        // `remove` is what assemble builds: the ambient scrub, then out-of-scope secrets.
        let profile = vec!["default".to_string()];
        let secrets = config.get_secrets(&profile).unwrap();
        let leases = config.get_leases(&profile).unwrap();
        let requested = ["BAR".to_string(), "FOO".to_string()];
        let sel = crate::child_env::select(
            &secrets,
            &leases,
            EnvScope::Exec,
            crate::child_env::Roots::Keys(&requested),
        )
        .unwrap();
        let resolved = IndexMap::from([
            ("FOO".to_string(), Some("foo".to_string())),
            ("BAR".to_string(), Some("bar".to_string())),
        ]);
        let expected = crate::child_env::assemble(
            EnvScope::Exec,
            &secrets,
            &leases,
            &sel,
            &resolved,
            &IndexMap::new(),
            Vec::new(),
        );
        assert_eq!(document.remove, expected.remove);
        assert!(document.remove.contains(&"HID".to_string()));
        assert!(document.remove.contains(&"FNOX_AGE_KEY".to_string()));
    }

    #[tokio::test]
    async fn resolve_env_hit_matches_the_cli_document() {
        let config = env_config(ENV_CONFIG);
        let state = seed(&config, "exec", &[("FOO", "foo"), ("BAR", "bar")]).await;
        // Every key in scope, minus the root that is never cached.
        let req = env_request(EnvScope::Exec, Some(&["FOO", "BAR"]));
        let Response::Env { document } = respond(&config, &req, None, &state).await else {
            panic!("expected a hit");
        };
        let profile = vec!["default".to_string()];
        let secrets = config.get_secrets(&profile).unwrap();
        let leases = config.get_leases(&profile).unwrap();
        let requested = ["FOO".to_string(), "BAR".to_string()];
        let sel = crate::child_env::select(
            &secrets,
            &leases,
            EnvScope::Exec,
            crate::child_env::Roots::Keys(&requested),
        )
        .unwrap();
        let resolved = IndexMap::from([
            ("FOO".to_string(), Some("foo".to_string())),
            ("BAR".to_string(), Some("bar".to_string())),
        ]);
        let cli_document = crate::child_env::env_document(
            EnvScope::Exec,
            profile,
            crate::child_env::assemble(
                EnvScope::Exec,
                &secrets,
                &leases,
                &sel,
                &resolved,
                &IndexMap::new(),
                Vec::new(),
            ),
        );
        assert_eq!(document, cli_document);
        assert_eq!(
            serde_json::to_string(&document).unwrap(),
            serde_json::to_string(&cli_document).unwrap()
        );
    }

    #[tokio::test]
    async fn resolve_env_reports_only_the_uncached_roots() {
        let config = env_config(ENV_CONFIG);
        let state = seed(&config, "exec", &[("FOO", "foo")]).await;
        let req = env_request(EnvScope::Exec, Some(&["FOO", "BAR"]));
        let Response::EnvMiss { keys } = respond(&config, &req, None, &state).await else {
            panic!("expected a miss");
        };
        assert_eq!(keys, ["BAR"]);
    }

    #[tokio::test]
    async fn resolve_env_never_serves_a_root_that_opts_out_of_the_cache() {
        let config = env_config(ENV_CONFIG);
        let state = seed(&config, "exec", &[("NOCACHE", "nc")]).await;
        // Even an entry placed in the cache by hand is ignored.
        let secrets = config.get_secrets(&["default".to_string()]).unwrap();
        let fingerprint = config_fingerprint(&config, &[]).unwrap();
        state.lock().await.cache.insert(
            cache_key(
                &fingerprint,
                &["default".to_string()],
                "NOCACHE",
                &secrets["NOCACHE"],
                false,
                "exec",
            ),
            Some("nc".to_string()),
        );
        let req = env_request(EnvScope::Exec, Some(&["NOCACHE"]));
        let Response::EnvMiss { keys } = respond(&config, &req, None, &state).await else {
            panic!("expected a miss");
        };
        assert_eq!(keys, ["NOCACHE"]);
    }

    #[tokio::test]
    async fn resolve_env_misses_when_a_lease_produces_a_requested_key() {
        let config = env_config(&format!(
            "{ENV_CONFIG}\n[leases.gh]\ntype = \"github-app\"\napp_id = \"1\"\ninstallation_id = \"2\"\nenv_var = \"GH_TOKEN\"\n"
        ));
        let state = seed(&config, "exec", &[("FOO", "foo")]).await;
        let req = env_request(EnvScope::Exec, Some(&["FOO", "GH_TOKEN"]));
        let Response::EnvMiss { keys } = respond(&config, &req, None, &state).await else {
            panic!("expected a miss");
        };
        assert_eq!(keys, ["GH_TOKEN"]);
        // Without --keys, the statically known keys of the selected lease.
        let req = env_request(EnvScope::Exec, None);
        let Response::EnvMiss { keys } = respond(&config, &req, None, &state).await else {
            panic!("expected a miss");
        };
        assert_eq!(keys, ["GH_TOKEN"]);
    }

    #[tokio::test]
    async fn resolve_env_without_keys_serves_every_cached_root_in_scope() {
        let config = env_config(ENV_CONFIG);
        let state = seed(
            &config,
            "exec",
            &[("FOO", "foo"), ("BAR", "bar"), ("NOCACHE", "nc")],
        )
        .await;
        // NOCACHE is in scope and never cached, so everything misses.
        let req = env_request(EnvScope::Exec, None);
        let Response::EnvMiss { keys } = respond(&config, &req, None, &state).await else {
            panic!("expected a miss");
        };
        assert_eq!(keys, ["NOCACHE"]);

        let config = env_config(&ENV_CONFIG.replace(
            "NOCACHE = { provider = \"plain\", value = \"nc\", daemon_cache = false }\n",
            "",
        ));
        let state = seed(&config, "exec", &[("FOO", "foo"), ("BAR", "bar")]).await;
        let Response::Env { document } = respond(&config, &req, None, &state).await else {
            panic!("expected a hit");
        };
        assert_eq!(document.set.len(), 2);
    }

    #[tokio::test]
    async fn resolve_env_derives_the_cache_purpose_from_the_scope() {
        let config = env_config(ENV_CONFIG);
        let state = seed(&config, "exec", &[("FOO", "foo")]).await;
        let shell = env_request(EnvScope::Shell, Some(&["FOO"]));
        assert!(matches!(
            respond(&config, &shell, None, &state).await,
            Response::EnvMiss { .. }
        ));
        seed_into(&state, &config, "hook-env", &[("FOO", "foo")]).await;
        assert!(matches!(
            respond(&config, &shell, None, &state).await,
            Response::Env { .. }
        ));
        // `env = "exec"` is not injectable into a shell.
        let bar = env_request(EnvScope::Shell, Some(&["BAR"]));
        assert!(matches!(
            respond(&config, &bar, None, &state).await,
            Response::EnvRejected(_)
        ));
    }

    #[tokio::test]
    async fn resolve_env_checks_the_protocol_before_anything_else() {
        for protocol in [5, 7] {
            let mut req = env_request(EnvScope::Exec, None);
            req.protocol = protocol;
            // The request's cwd and config do not exist; the protocol check comes first.
            req.cwd = PathBuf::from("/nonexistent/fnox-test");
            let response = process_request(
                Request::ResolveEnv(req),
                empty_state(),
                Arc::new(Mutex::new(())),
            )
            .await
            .unwrap();
            assert!(
                matches!(response, Response::UnsupportedProtocol { min: 6, max: 6 }),
                "{response:?}"
            );
            let response = process_request(
                Request::Hello { protocol },
                empty_state(),
                Arc::new(Mutex::new(())),
            )
            .await
            .unwrap();
            assert!(matches!(
                response,
                Response::UnsupportedProtocol { min: 6, max: 6 }
            ));
        }
    }

    #[tokio::test]
    async fn hello_reports_the_protocol_range_and_pid() {
        let response = process_request(
            Request::Hello { protocol: 6 },
            empty_state(),
            Arc::new(Mutex::new(())),
        )
        .await
        .unwrap();
        let Response::Hello {
            protocol,
            min_protocol,
            fnox_version,
            pid,
        } = response
        else {
            panic!("expected hello");
        };
        assert_eq!((protocol, min_protocol), (6, 6));
        assert_eq!(fnox_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(pid, std::process::id());
    }

    // ---- socket key parity ----

    fn parity_cli() -> crate::commands::Cli {
        crate::commands::Cli {
            config: PathBuf::from("fnox.toml"),
            profile: Vec::new(),
            verbose: false,
            age_key_file: None,
            if_missing: None,
            no_color: false,
            no_daemon: false,
            no_defaults: false,
            non_interactive: false,
            write_profile: None,
            command: crate::commands::Commands::Version(crate::commands::version::VersionCommand),
        }
    }

    /// What the fnox CLI builds its settings from, for these environment variables.
    fn cli_socket_key(
        env: &[(&str, &str)],
    ) -> Result<fnox_client::SocketKey, impl std::fmt::Debug> {
        let layer = usage_rs::config::EnvLayer::new(
            env.iter().map(|(k, v)| (k.to_string(), v.to_string())),
        );
        let settings = crate::settings::Settings::from_layers(None, &layer)?;
        Ok::<_, miette::Report>(
            ResolveContext::from_cli_and_settings(&parity_cli(), Some(&settings)).socket_key(),
        )
    }

    // V3: the boolean words usage-rs accepts, and everything else the client must agree on.
    #[test]
    fn socket_key_matches_what_the_cli_resolves() {
        use fnox_client::{CliFlags, SocketKey};
        let home = std::env::var("HOME").expect("HOME is set for tests");
        let mut cases: Vec<Vec<(&str, String)>> = vec![Vec::new()];
        for profile in ["staging, prod", "../bad", "", "dev", "a,,b", "ok,../bad"] {
            cases.push(vec![("FNOX_PROFILE", profile.to_string())]);
        }
        for word in [
            "1", "true", "TRUE", "True", "yes", "Yes", "y", "Y", "on", "ON", "0", "false", "no",
            "n", "off", "OFF", "",
        ] {
            cases.push(vec![("FNOX_NO_DEFAULTS", word.to_string())]);
        }
        for value in ["warn", "error", ""] {
            cases.push(vec![("FNOX_IF_MISSING", value.to_string())]);
        }
        for value in ["~/k", "/abs/k", "~", "~other/k", "rel/k", ""] {
            cases.push(vec![("FNOX_AGE_KEY_FILE", value.to_string())]);
        }
        cases.push(vec![
            ("FNOX_PROFILE", "staging, prod".to_string()),
            ("FNOX_NO_DEFAULTS", "on".to_string()),
            ("FNOX_IF_MISSING", "ignore".to_string()),
            ("FNOX_AGE_KEY_FILE", "~/k".to_string()),
        ]);

        for case in cases {
            let env: Vec<(&str, &str)> = case.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let cli = cli_socket_key(&env).expect("these inputs resolve");
            // The client reads HOME from the environment it is given.
            let get = |name: &str| {
                if name == "HOME" {
                    return Some(home.clone());
                }
                env.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            };
            let client = SocketKey::from_cli_env(&CliFlags::default(), &get);
            assert_eq!(client, cli, "environment: {env:?}");
        }
    }

    // `maybe` is not a boolean word. fnox resolves its settings without it
    // (the default stands), and the client reads it as false: the same key.
    #[test]
    fn an_unrecognized_boolean_word_is_false_for_the_client() {
        use fnox_client::{CliFlags, SocketKey};
        let cli = cli_socket_key(&[("FNOX_NO_DEFAULTS", "maybe")]).expect("resolves");
        let get = |name: &str| (name == "FNOX_NO_DEFAULTS").then(|| "maybe".to_string());
        let client = SocketKey::from_cli_env(&CliFlags::default(), &get);
        assert_eq!(client, cli);
        assert_eq!(client, SocketKey::new(&[], false, None, None));
    }

    #[test]
    fn the_settings_registry_is_reachable_from_tests() {
        // V8
        assert!(
            crate::settings::SettingsData::SETTINGS_REGISTRY
                .lookup("no_defaults")
                .is_some()
        );
    }

    #[test]
    fn cli_flags_override_the_environment_in_the_context() {
        let mut cli = parity_cli();
        cli.profile = vec!["cli".to_string()];
        cli.no_defaults = true;
        cli.if_missing = Some("error".to_string());
        let layer = usage_rs::config::EnvLayer::new([
            ("FNOX_PROFILE".to_string(), "env".to_string()),
            ("FNOX_IF_MISSING".to_string(), "ignore".to_string()),
        ]);
        let settings = crate::settings::Settings::from_layers(None, &layer).unwrap();
        let key = ResolveContext::from_cli_and_settings(&cli, Some(&settings)).socket_key();
        let flags = fnox_client::CliFlags {
            profile: vec!["cli".to_string()],
            no_defaults: true,
            if_missing: Some("error".to_string()),
        };
        let get = |name: &str| match name {
            "FNOX_PROFILE" => Some("env".to_string()),
            "FNOX_IF_MISSING" => Some("ignore".to_string()),
            _ => None,
        };
        assert_eq!(fnox_client::SocketKey::from_cli_env(&flags, &get), key);
    }
}
