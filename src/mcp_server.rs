use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use indexmap::IndexMap;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars;
use rmcp::service::{ElicitationError, ElicitationMode, RequestContext};
use rmcp::{ErrorData as McpError, Peer, RoleServer, ServerHandler};
use rmcp::{tool, tool_router};
use tokio::sync::{OnceCell, RwLock};

use crate::commands::set::{SetCommand, local_target_path, storage_provider, stores_securely};
use crate::config::{self, Config, McpConfig, McpTool, SecretConfig};
use crate::daemon::{Purpose, ResolveContext};
use crate::generate::GenerateKind;
use crate::mcp_secret_page::{PageDetails, SecretPage, Submission};
use crate::temp_file_secrets::create_ephemeral_secret_file;

/// Maximum output size (1 MiB) to prevent unbounded memory usage
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Per-stream (stdout/stderr) read limit. Half the total budget + 1 byte
/// so we can detect truncation when a single stream overflows.
const PER_STREAM_LIMIT: usize = (MAX_OUTPUT_BYTES / 2) + 1;

/// Default execution timeout (5 minutes)
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 300;

/// How long request_secret waits for the user to enter a value
const REQUEST_SECRET_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Longest agent-written reason the secret page shows
const MAX_REASON_CHARS: usize = 500;

fn scrub_age_identity(cmd: &mut tokio::process::Command) {
    for key in crate::child_env::ambient_scrub_keys() {
        cmd.env_remove(key);
    }
}

/// MCP tool parameter: request a secret by name
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetSecretParams {
    /// The name of the secret to retrieve (must match a key in fnox.toml secrets)
    pub name: String,
}

/// MCP tool parameter: execute a command with secrets injected
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecParams {
    /// The command and arguments to execute as a list where the first element is the program and the rest are arguments.
    /// No shell is invoked — env vars are NOT expanded in argument strings. The injected secrets are available
    /// as environment variables that the command reads through its own API. To use shell expansion, pass
    /// ["sh", "-c", "your shell command here"].
    pub command: Vec<String>,
}

/// MCP tool parameter: ask the user to enter a secret
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RequestSecretParams {
    /// The secret's name, which is also its environment variable name, such as TAILSCALE_AUTHKEY
    pub name: String,
    /// Why the secret is needed and where the user can create it. Shown to the user next to the input box.
    #[serde(default)]
    pub reason: Option<String>,
    /// Ask for a new value even if the secret already has one
    #[serde(default)]
    pub replace: bool,
}

/// The fnox MCP server — acts as a session-scoped secret broker.
///
/// Secrets are resolved on first access (may require yubikey/SSO) and cached
/// in memory for the session. `as_file = true` secrets are written to
/// ephemeral temp files scoped to each exec call.
#[derive(Clone)]
pub struct FnoxMcpServer {
    config: Arc<Config>,
    profile: Arc<Vec<String>>,
    mcp_config: Arc<McpConfig>,
    daemon_context: Arc<ResolveContext>,
    /// Replaced, not mutated, when request_secret stores a new secret
    profile_secrets: Arc<std::sync::RwLock<Arc<IndexMap<String, SecretConfig>>>>,
    /// `--config` value, for finding the file request_secret writes to
    config_path: Arc<PathBuf>,
    /// `--write-profile` value, for request_secret
    write_profile: Arc<Option<String>>,
    /// Held while request_secret rechecks and stores a value, so two pages
    /// can't both pass the recheck and overwrite each other
    store_lock: Arc<tokio::sync::Mutex<()>>,
    /// Names request_secret sent to `fnox set` in the terminal; their next
    /// check reloads the value instead of trusting the cache
    sent_to_terminal: Arc<std::sync::Mutex<HashSet<String>>>,
    /// Resolved secret values (raw). None means "resolved but absent".
    /// as_file conversion happens at exec time.
    cache: Arc<RwLock<HashMap<String, Option<String>>>>,
    /// Tracks whether secrets have been resolved (separate from cache emptiness,
    /// since all secrets may resolve to None for optional/absent secrets).
    resolved: Arc<OnceCell<()>>,
    tool_router: ToolRouter<FnoxMcpServer>,
}

#[tool_router]
impl FnoxMcpServer {
    pub fn new(
        config: Config,
        profile: Vec<String>,
        mcp_config: McpConfig,
        daemon_context: ResolveContext,
        profile_secrets: IndexMap<String, SecretConfig>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            profile: Arc::new(profile),
            mcp_config: Arc::new(mcp_config),
            daemon_context: Arc::new(daemon_context),
            profile_secrets: Arc::new(std::sync::RwLock::new(Arc::new(profile_secrets))),
            config_path: Arc::new(PathBuf::from(config::DEFAULT_CONFIG_FILENAME)),
            write_profile: Arc::new(None),
            store_lock: Arc::new(tokio::sync::Mutex::new(())),
            sent_to_terminal: Arc::new(std::sync::Mutex::new(HashSet::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            resolved: Arc::new(OnceCell::new()),
            tool_router: Self::tool_router(),
        }
    }

    /// Set the `--config` and `--write-profile` values that decide where
    /// request_secret stores a value, as `fnox set` would
    pub fn with_write_target(
        mut self,
        config_path: PathBuf,
        write_profile: Option<String>,
    ) -> Self {
        self.config_path = Arc::new(config_path);
        self.write_profile = Arc::new(write_profile);
        self
    }

    /// The secrets this session can reach
    fn secrets(&self) -> Arc<IndexMap<String, SecretConfig>> {
        self.profile_secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// as_file secrets are meant to be consumed as file paths via exec, not
    /// retrieved as raw content. Reject them to avoid leaking key material.
    fn reject_as_file(&self, name: &str) -> Result<(), McpError> {
        if self.secrets().get(name).is_some_and(|sc| sc.as_file) {
            return Err(McpError::invalid_request(
                format!(
                    "Secret '{name}' is configured with as_file=true and can only be used via the exec tool"
                ),
                None,
            ));
        }
        Ok(())
    }

    /// Make a secret stored during this session available to the tools
    async fn add_secret(&self, name: &str, secret: SecretConfig, value: String) {
        {
            let mut secrets = self
                .profile_secrets
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let mut updated = (**secrets).clone();
            updated.insert(name.to_string(), secret);
            *secrets = Arc::new(updated);
        }
        self.cache
            .write()
            .await
            .insert(name.to_string(), Some(value));
    }

    fn list_tools_result(&self) -> ListToolsResult {
        let all_tools = self.tool_router.list_all();
        let tools = self.mcp_config.tools();
        let enabled: Vec<&str> = tools.iter().map(|t| t.tool_name()).collect();
        let filtered = all_tools
            .into_iter()
            .filter(|t| enabled.contains(&t.name.as_ref()))
            .collect();

        ListToolsResult::with_all_items(filtered)
            .with_ttl_ms(0)
            .with_cache_scope(CacheScope::Private)
    }

    /// Ensure env-injectable secrets are resolved and cached. First call
    /// resolves the batch (amortizes yubikey/SSO cost); subsequent calls are
    /// no-ops.
    ///
    /// env=false secrets are NOT resolved here — they are more sensitive and
    /// resolved on-demand by `get_secret` to avoid unnecessary auth prompts.
    /// env="exec" secrets ARE resolved: the exec tool needs them in cache.
    async fn ensure_resolved(&self) -> Result<(), McpError> {
        let config = self.config.clone();
        let profile = self.profile.clone();
        let profile_secrets = self.secrets();
        let daemon_context = self.daemon_context.clone();
        let cache = self.cache.clone();

        self.resolved
            .get_or_try_init(|| async {
                // Only batch-resolve env-injectable secrets; env=false are deferred.
                // Skip any that request_secret already cached: their config
                // may name a provider this session's config predates.
                let env_secrets: IndexMap<String, SecretConfig> = {
                    let cached = cache.read().await;
                    profile_secrets
                        .iter()
                        .filter(|(k, sc)| sc.env_mode().in_exec() && !cached.contains_key(*k))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                };

                // include_all_modes=true: the map above is already filtered,
                // and env="exec" secrets would otherwise be dropped by the
                // shell-only filter in resolve_batch.
                let resolved = crate::daemon::resolve_batch_with_context(
                    &daemon_context,
                    &config,
                    &profile,
                    &env_secrets,
                    Purpose::Mcp,
                    true,
                )
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to resolve secrets: {e}"), None)
                })?;

                // request_secret may have stored one of these while the batch
                // ran; keep its newer value
                let mut cache = cache.write().await;
                for (key, value) in resolved {
                    cache.entry(key).or_insert(value);
                }

                Ok(())
            })
            .await?;

        Ok(())
    }

    /// Resolve a single env=false secret on demand and cache it.
    /// Returns the cached value if already resolved, or None for absent secrets.
    /// Caches None results so absent optional secrets don't re-trigger auth.
    async fn resolve_single(&self, name: &str) -> Result<Option<String>, McpError> {
        // Check cache first (Some(Some(_)) = present, Some(None) = known absent)
        {
            let cache = self.cache.read().await;
            if let Some(v) = cache.get(name) {
                return Ok(v.clone());
            }
        }

        let profile_secrets = self.secrets();
        let secret_config = match profile_secrets.get(name) {
            Some(sc) => sc,
            None => return Ok(None),
        };

        // Build a single-entry map for resolve_secrets_batch
        let single: IndexMap<String, SecretConfig> = [(name.to_string(), secret_config.clone())]
            .into_iter()
            .collect();

        let resolved = crate::daemon::resolve_batch_with_context(
            &self.daemon_context,
            &self.config,
            &self.profile,
            &single,
            Purpose::Mcp,
            true,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(format!("Failed to resolve secret '{name}': {e}"), None)
        })?;

        let value = resolved.into_iter().next().and_then(|(_, v)| v);

        let mut cache = self.cache.write().await;
        // Re-check under write lock to avoid TOCTOU race: another concurrent
        // get_secret may have resolved and cached this while we were waiting.
        if let Some(existing) = cache.get(name) {
            return Ok(existing.clone());
        }
        // Cache both present and absent (None) values to avoid re-triggering auth
        cache.insert(name.to_string(), value.clone());
        Ok(value)
    }

    /// Write a secret value to a temp file and return the path.
    /// The temp file handle is pushed to `temp_files` to keep it alive.
    fn create_secret_file(
        key: &str,
        value: &str,
        temp_files: &mut Vec<tempfile::NamedTempFile>,
    ) -> Result<String, McpError> {
        let temp_file = create_ephemeral_secret_file(key, value).map_err(|e| {
            McpError::internal_error(
                format!("Failed to create temp file for secret '{key}': {e}"),
                None,
            )
        })?;
        let file_path = temp_file.path().to_string_lossy().to_string();
        temp_files.push(temp_file);
        Ok(file_path)
    }

    /// Retrieve a single secret by name.
    ///
    /// env=true and env="exec" secrets are resolved eagerly in the first
    /// batch. env=false secrets are resolved on-demand here (may trigger auth)
    /// and cached for subsequent calls.
    #[tool(description = "Get a secret value by name from the fnox configuration")]
    async fn get_secret(
        &self,
        Parameters(params): Parameters<GetSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        if !self.mcp_config.tools().contains(&McpTool::GetSecret) {
            return Err(McpError::invalid_request(
                "Tool 'get_secret' is not enabled in this configuration",
                None,
            ));
        }

        self.reject_as_file(&params.name)?;

        // Ensure env-injectable secrets (env=true / env="exec") are batch-resolved
        self.ensure_resolved().await?;
        // request_secret may have changed the secret while this waited, so
        // read the current map and check again before returning a value
        let profile_secrets = self.secrets();

        // Check cache (covers env=true/env="exec" secrets and previously
        // resolved env=false).
        // Some(Some(v)) = present, Some(None) = known absent, None = not yet resolved.
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&params.name) {
                return match cached {
                    Some(value) => {
                        self.reject_as_file(&params.name)?;
                        Ok(CallToolResult::success(vec![ContentBlock::text(
                            value.clone(),
                        )]))
                    }
                    None => Err(McpError::invalid_request(
                        format!(
                            "Secret '{}' has no value (it may be optional and absent)",
                            params.name
                        ),
                        None,
                    )),
                };
            }
        }

        // Not in cache — check if it's a configured secret
        if let Some(secret_config) = profile_secrets.get(&params.name) {
            // env=false secrets are deferred; try on-demand resolution
            if !secret_config.env_mode().in_exec() {
                return match self.resolve_single(&params.name).await? {
                    Some(value) => {
                        self.reject_as_file(&params.name)?;
                        Ok(CallToolResult::success(vec![ContentBlock::text(value)]))
                    }
                    None => Err(McpError::invalid_request(
                        format!(
                            "Secret '{}' has no value (it may be optional and absent)",
                            params.name
                        ),
                        None,
                    )),
                };
            }
            // env=true or env="exec" but not in cache — should not happen
            // after ensure_resolved, but handle gracefully
            Err(McpError::invalid_request(
                format!(
                    "Secret '{}' has no value (it may be optional and absent)",
                    params.name
                ),
                None,
            ))
        } else {
            Err(McpError::invalid_params(
                format!("Secret '{}' not found in configuration", params.name),
                None,
            ))
        }
    }

    /// Execute a command with secrets injected as environment variables.
    #[tool(
        description = "Execute a command with secrets injected as environment variables. Returns the command's stdout and stderr."
    )]
    async fn exec(
        &self,
        Parameters(params): Parameters<ExecParams>,
    ) -> Result<CallToolResult, McpError> {
        if !self.mcp_config.tools().contains(&McpTool::Exec) {
            return Err(McpError::invalid_request(
                "Tool 'exec' is not enabled in this configuration",
                None,
            ));
        }

        if params.command.is_empty() || params.command[0].is_empty() {
            return Err(McpError::invalid_params("Command must not be empty", None));
        }

        self.ensure_resolved().await?;
        let profile_secrets = self.secrets();

        // Snapshot env vars from cache, filtering out env=false and absent
        // secrets (env="exec" is injected: exec subprocesses are its intended
        // destination). This releases the read lock before the potentially
        // long subprocess.
        let env_vars: Vec<(String, String)> = {
            let cache = self.cache.read().await;
            cache
                .iter()
                .filter(|(key, _)| {
                    profile_secrets
                        .get(key.as_str())
                        .is_some_and(|sc| sc.env_mode().in_exec())
                })
                .filter_map(|(k, v)| v.as_ref().map(|val| (k.clone(), val.clone())))
                .collect()
        };

        // For as_file secrets, write raw values to temp files and inject the
        // file path as the env var. Temp files are kept alive until the
        // subprocess completes (held in _exec_temp_files).
        let mut _exec_temp_files = Vec::new();

        let cmd_name = &params.command[0];

        #[cfg(windows)]
        let cmd_path = which::which(cmd_name).unwrap_or_else(|_| cmd_name.into());
        #[cfg(not(windows))]
        let cmd_path = cmd_name;

        let mut cmd = tokio::process::Command::new(cmd_path);
        // MCP subprocesses must receive resolved secrets, not the ambient age
        // identity that can decrypt other values in the configuration.
        // Explicitly configured secrets with these names are injected below.
        scrub_age_identity(&mut cmd);
        if params.command.len() > 1 {
            cmd.args(&params.command[1..]);
        }

        // Inject filtered secrets as env vars, converting as_file to temp paths
        for (key, value) in &env_vars {
            if let Some(sc) = profile_secrets.get(key.as_str())
                && sc.as_file
            {
                let path = Self::create_secret_file(key, value, &mut _exec_temp_files)?;
                cmd.env(key, &path);
            } else {
                cmd.env(key, value);
            }
        }

        // Strip env=false secrets that resolve_secrets_batch may have set
        // as process env vars (side effect of dependency resolution).
        for (key, secret_config) in profile_secrets.iter() {
            if !secret_config.env_mode().in_exec() {
                cmd.env_remove(key);
            }
        }

        // Must NOT inherit stdio — would corrupt JSON-RPC stream
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // kill_on_drop ensures the child is killed if the future is cancelled
        // (e.g. on timeout), preventing orphaned/zombie processes.
        cmd.kill_on_drop(true);

        let timeout_secs = self
            .mcp_config
            .exec_timeout_secs
            .unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS);
        let mut child = cmd.spawn().map_err(|e| {
            McpError::internal_error(
                format!("Failed to execute command '{}': {e}", params.command[0]),
                None,
            )
        })?;

        // Read stdout/stderr concurrently with bounded buffers to prevent both
        // OOM and pipe deadlocks (sequential reads can deadlock if the child
        // fills one pipe buffer while we're blocked reading the other).
        let mut child_stdout = child.stdout.take();
        let mut child_stderr = child.stderr.take();

        let collect_bounded = async {
            use tokio::io::AsyncReadExt;
            // Split budget: half for stdout, half for stderr (+1 each to detect truncation)
            let per_stream_limit = PER_STREAM_LIMIT;

            let stdout_fut = async {
                let mut buf = Vec::with_capacity(per_stream_limit.min(65536));
                if let Some(ref mut out) = child_stdout {
                    out.take(per_stream_limit as u64)
                        .read_to_end(&mut buf)
                        .await
                        .ok();
                }
                drop(child_stdout);
                buf
            };

            let stderr_fut = async {
                let mut buf = Vec::with_capacity(per_stream_limit.min(65536));
                if let Some(ref mut err) = child_stderr {
                    err.take(per_stream_limit as u64)
                        .read_to_end(&mut buf)
                        .await
                        .ok();
                }
                drop(child_stderr);
                buf
            };

            let (stdout_buf, stderr_buf) = tokio::join!(stdout_fut, stderr_fut);
            let status = child.wait().await;
            (stdout_buf, stderr_buf, status)
        };

        let (stdout_buf, stderr_buf, status) = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            collect_bounded,
        )
        .await
        .map_err(|_| {
            // child is dropped here → kill_on_drop sends SIGKILL
            McpError::internal_error(
                format!(
                    "Command '{}' timed out after {timeout_secs}s",
                    params.command[0]
                ),
                None,
            )
        })?;

        let status = status.map_err(|e| {
            McpError::internal_error(
                format!("Failed to wait for command '{}': {e}", params.command[0]),
                None,
            )
        })?;

        let per_stream_cap = PER_STREAM_LIMIT;
        let total_collected = stdout_buf.len() + stderr_buf.len();
        let stdout_truncated = stdout_buf.len() >= per_stream_cap;
        let stderr_truncated = stderr_buf.len() >= per_stream_cap;
        let truncated = stdout_truncated || stderr_truncated || total_collected > MAX_OUTPUT_BYTES;

        let display_limit = PER_STREAM_LIMIT - 1;
        let stdout_raw =
            String::from_utf8_lossy(&stdout_buf[..stdout_buf.len().min(display_limit)]);
        let stderr_raw =
            String::from_utf8_lossy(&stderr_buf[..stderr_buf.len().min(display_limit)]);

        // Redact secret values from output to prevent exfiltration via
        // commands like `printenv` or `echo $SECRET`.
        let (stdout, stderr) = if self.mcp_config.redact_output() {
            (
                redact_secrets(&stdout_raw, &env_vars)?,
                redact_secrets(&stderr_raw, &env_vars)?,
            )
        } else {
            (stdout_raw.to_string(), stderr_raw.to_string())
        };

        let mut parts = Vec::new();
        if !stdout.is_empty() {
            parts.push(stdout);
        }
        if !stderr.is_empty() {
            parts.push(format!("[stderr]\n{stderr}"));
        }

        let exit_code = status.code().unwrap_or(-1);
        if !status.success() || parts.is_empty() {
            parts.push(format!("[exit code: {exit_code}]"));
        }
        if truncated {
            if stdout_truncated || stderr_truncated {
                let stream_limit = per_stream_cap - 1;
                parts.push(format!(
                    "[output truncated: per-stream limit of {stream_limit} bytes exceeded (total collected: {total_collected} bytes)]"
                ));
            } else {
                parts.push(format!(
                    "[output truncated: {total_collected} bytes exceeded {MAX_OUTPUT_BYTES} byte limit]"
                ));
            }
        }

        let text = parts.join("\n");
        if status.success() {
            Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
        } else {
            Ok(CallToolResult::error(vec![ContentBlock::text(text)]))
        }
    }

    /// Ask the user to enter a secret on a one-time local page.
    ///
    /// The page's URL reaches the user through URL-mode elicitation, so the
    /// value never passes through the client. fnox stores it the way `fnox set`
    /// would, and the agent learns only that it was stored.
    #[tool(
        description = "Ask the user to enter a secret that isn't set yet, such as an API key or auth token. fnox shows the user a local page to type it into, stores it, and makes it available to the exec tool as an environment variable. The value is never returned to you. Use this instead of asking the user to paste a secret into the chat."
    )]
    async fn request_secret(
        &self,
        Parameters(params): Parameters<RequestSecretParams>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if !self.mcp_config.tools().contains(&McpTool::RequestSecret) {
            return Err(McpError::invalid_request(
                "Tool 'request_secret' is not enabled in this configuration",
                None,
            ));
        }
        let name = params.name;
        config::validate_secret_name(&name)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        if let Some(allowlist) = &self.mcp_config.secrets
            && !allowlist.contains(&name)
        {
            return Err(McpError::invalid_request(
                format!("Secret '{name}' is not in mcp.secrets, so it can't be requested"),
                None,
            ));
        }

        let config = Config::load_smart(self.config_path.as_path())
            .map_err(|e| McpError::internal_error(format!("Failed to load config: {e}"), None))?;
        if !params.replace && self.has_value(&config, &name).await? {
            return Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                "Secret '{name}' already has a value. Use exec to run commands with it, or call request_secret with replace=true to ask the user for a new value."
            ))]));
        }

        // Refuse a provider that would leave the value in plain text before
        // the user types anything, on the page or in the terminal
        let provider = self.secure_provider(&config, &name).await?;

        if !peer
            .supported_elicitation_modes()
            .contains(&ElicitationMode::Url)
        {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                self.terminal_fallback(&name),
            )]));
        }

        let internal = |e: crate::error::FnoxError| McpError::internal_error(e.to_string(), None);
        let write_profile =
            Config::resolve_write_profile(&self.profile, self.write_profile.as_deref())
                .map_err(internal)?;
        let target = local_target_path(
            &self.config_path,
            &self.profile,
            self.write_profile.as_deref(),
        )
        .map_err(internal)?;

        let reason = params
            .reason
            .map(|reason| reason.chars().take(MAX_REASON_CHARS).collect());
        // One deadline covers opening the link and submitting the page; the
        // page stops serving when this call returns
        let deadline = tokio::time::Instant::now() + REQUEST_SECRET_TIMEOUT;
        let mut page = SecretPage::start(PageDetails {
            name: name.clone(),
            reason,
            provider: provider.clone(),
            target: target.clone(),
            profile: write_profile,
        })
        .await
        .map_err(internal)?;

        let elicitation_id = data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>());
        let message = format!(
            "fnox needs a value for {name}. Open this local page to enter it. fnox stores it with provider '{provider}' and does not show it to the agent."
        );
        match peer
            .elicit_url_with_timeout(
                message,
                page.url().clone(),
                elicitation_id,
                Some(deadline.saturating_duration_since(tokio::time::Instant::now())),
            )
            .await
        {
            Ok(ElicitationAction::Accept) => {}
            Ok(_) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "The user declined to open the page for '{name}'. Don't ask for the value in the chat."
                ))]));
            }
            Err(ElicitationError::CapabilityNotSupported) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    self.terminal_fallback(&name),
                )]));
            }
            Err(e) => {
                return Err(McpError::internal_error(
                    format!("Failed to show the secret page link: {e}"),
                    None,
                ));
            }
        }

        // Accepting the elicitation only means the user opened the link; the
        // value arrives when they submit the page.
        let submission = tokio::time::timeout_at(deadline, page.next())
            .await
            .ok()
            .flatten();
        match submission {
            None => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Timed out waiting for the user to enter '{name}'."
            ))])),
            Some(Submission::Declined) => {
                Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "The user declined to enter '{name}'. Don't ask for the value in the chat."
                ))]))
            }
            Some(Submission::Value { value, reply }) => {
                // One store at a time, so two pages for the same name can't
                // both pass the recheck
                let _store = self.store_lock.lock().await;
                // The config may have changed while the page was open
                let saved = match self.recheck(&name, params.replace, &provider).await {
                    Ok(config) => self.save(&name, value, config, &target).await,
                    Err(e) => Err(e),
                };
                if let Err(e) = saved {
                    let _ = reply.send(Err(e.to_string()));
                    return Err(McpError::internal_error(
                        format!("Failed to store '{name}': {e}"),
                        None,
                    ));
                }
                let stored = format!(
                    "fnox stored it with provider '{provider}' in {}",
                    target.display()
                );
                if let Err(e) = self.reload_stored(&name).await {
                    let _ = reply.send(Ok(format!(
                        "fnox stored {name}, but couldn't read it back: {e}"
                    )));
                    return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "The user entered '{name}' and {stored}, but reading it back failed: {e}. The value is saved; don't ask for it again."
                    ))]));
                }
                let _ = reply.send(Ok(format!(
                    "fnox stored {name}. You can close this tab and go back to the agent."
                )));
                let usage = if self
                    .secrets()
                    .get(&name)
                    .is_some_and(|secret| secret.env_mode().in_exec())
                {
                    format!("The exec tool now sets it as ${name}.")
                } else {
                    "Its env setting keeps it out of commands that the exec tool runs.".into()
                };
                Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                    "The user entered '{name}'. {stored}. {usage}"
                ))]))
            }
        }
    }

    /// The provider a new value for `name` would be stored with, refusing one
    /// that would leave it in plain text in the config
    async fn secure_provider(&self, config: &Config, name: &str) -> Result<String, McpError> {
        let internal = |e: crate::error::FnoxError| McpError::internal_error(e.to_string(), None);
        let write_profile =
            Config::resolve_write_profile(&self.profile, self.write_profile.as_deref())
                .map_err(internal)?;
        let write_stack = std::slice::from_ref(&write_profile);
        let effective = config
            .get_secret(write_stack, name)
            .map_err(internal)?
            .cloned();
        let Some(provider) =
            storage_provider(config, &write_profile, None, effective.as_ref()).map_err(internal)?
        else {
            return Err(McpError::invalid_request(
                format!(
                    "Secret '{name}' has no provider and the config sets no default_provider, so fnox would store it in plain text. Ask the user to set default_provider."
                ),
                None,
            ));
        };
        let providers = config.get_providers(write_stack).map_err(internal)?;
        let Some(provider_config) = providers.get(&provider) else {
            return Err(McpError::invalid_request(
                format!("Provider '{provider}' not found in configuration"),
                None,
            ));
        };
        let capabilities = crate::providers::get_provider_resolved(
            config,
            write_stack,
            &provider,
            provider_config,
        )
        .await
        .map_err(internal)?
        .capabilities();
        if !stores_securely(provider_config, &capabilities) {
            return Err(McpError::invalid_request(
                format!(
                    "Provider '{provider}' would leave '{name}' in plain text in the config. Ask the user to set default_provider to a provider that encrypts values or stores them remotely."
                ),
                None,
            ));
        }
        Ok(provider)
    }

    /// Reload the config after the user submits and check that storing still
    /// matches what the page showed: no value set meanwhile (unless
    /// replacing), and the same secure provider
    async fn recheck(
        &self,
        name: &str,
        replace: bool,
        provider: &str,
    ) -> crate::error::Result<Config> {
        let config = Config::load_smart(self.config_path.as_path())?;
        let changed = |message: String| crate::error::FnoxError::Config(message);
        if !replace
            && self
                .has_value(&config, name)
                .await
                .map_err(|e| changed(e.message.to_string()))?
        {
            return Err(changed(format!(
                "'{name}' was set while this page was open, so fnox stored nothing"
            )));
        }
        let current = self
            .secure_provider(&config, name)
            .await
            .map_err(|e| changed(e.message.to_string()))?;
        if current != provider {
            return Err(changed(format!(
                "the provider for '{name}' changed from '{provider}' to '{current}' while this page was open, so fnox stored nothing"
            )));
        }
        Ok(config)
    }

    /// Whether `name` resolves to a value, checking `config` (freshly loaded)
    /// for a secret set outside this session, such as with `fnox set`
    async fn has_value(&self, config: &Config, name: &str) -> Result<bool, McpError> {
        // After the terminal fallback, the user may have replaced a value this
        // session (and the daemon) still caches. Keep the mark until the
        // reload succeeds, so a retry after a failure still reloads.
        let sent_to_terminal = self
            .sent_to_terminal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(name);
        if sent_to_terminal {
            crate::daemon::refresh_with_context(
                &self.daemon_context,
                config,
                std::slice::from_ref(&name.to_string()),
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        } else if matches!(self.cache.read().await.get(name), Some(Some(_))) {
            return Ok(true);
        }
        let loaded = self.load(config, name).await.map_err(|e| {
            McpError::internal_error(
                format!(
                    "Secret '{name}' is configured but failed to resolve: {e}. Call request_secret with replace=true to ask the user for a new value."
                ),
                None,
            )
        })?;
        if sent_to_terminal {
            if !loaded {
                // Don't keep serving a value the config no longer has
                self.cache.write().await.remove(name);
            }
            self.sent_to_terminal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(name);
        }
        Ok(loaded)
    }

    /// Resolve `name` from `config` the way a new session would, and make it
    /// available to the tools if it has a value. Going through `get_secrets`
    /// and the resolver applies the top-level `env` default and settings such
    /// as `json_path`.
    async fn load(&self, config: &Config, name: &str) -> crate::error::Result<bool> {
        let Some(secret) = config.get_secrets(&self.profile)?.shift_remove(name) else {
            return Ok(false);
        };
        let single: IndexMap<String, SecretConfig> =
            [(name.to_string(), secret.clone())].into_iter().collect();
        let resolved = crate::daemon::resolve_batch_with_context(
            &self.daemon_context,
            config,
            &self.profile,
            &single,
            Purpose::Mcp,
            true,
        )
        .await?;
        match resolved.into_iter().next().and_then(|(_, value)| value) {
            Some(value) => {
                self.add_secret(name, secret, value).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Store a value the user entered, as `fnox set` would
    async fn save(
        &self,
        name: &str,
        value: String,
        config: Config,
        target: &std::path::Path,
    ) -> crate::error::Result<()> {
        let set = SetCommand {
            key: Some(name.to_string()),
            value: Some(value),
            description: None,
            global: false,
            key_name: None,
            dry_run: false,
            provider: None,
            base64_encode: false,
            default: None,
            file: None,
            force: false,
            from_file: None,
            generate: false,
            generate_type: GenerateKind::Password,
            if_missing: None,
            length: None,
            show: false,
            source: None,
        };
        set.store_at(
            config,
            &self.profile,
            self.write_profile.as_deref(),
            target,
            true,
        )
        .await?;
        Ok(())
    }

    /// Load a value `save` just stored, so the tools use it
    async fn reload_stored(&self, name: &str) -> crate::error::Result<()> {
        let config = Config::load_smart(self.config_path.as_path())?;
        // A remote provider keeps the same reference when a value is replaced,
        // so the daemon would otherwise keep serving the old value
        crate::daemon::refresh_with_context(
            &self.daemon_context,
            &config,
            std::slice::from_ref(&name.to_string()),
        )
        .await?;
        if !self.load(&config, name).await? {
            return Err(crate::error::FnoxError::Config(
                "it resolves to no value".into(),
            ));
        }
        Ok(())
    }

    /// What to tell the agent when the client can't show a URL
    fn terminal_fallback(&self, name: &str) -> String {
        self.sent_to_terminal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_string());
        let mut command = vec!["fnox".to_string()];
        if self.config_path.as_path() != std::path::Path::new(config::DEFAULT_CONFIG_FILENAME) {
            command.push("-c".into());
            command
                .push(crate::shell::posix_quote(&self.config_path.to_string_lossy()).into_owned());
        }
        if self.profile.as_slice() != ["default"] {
            command.push("-P".into());
            command.push(crate::shell::posix_quote(&self.profile.join(",")).into_owned());
        }
        if let Some(write_profile) = self.write_profile.as_deref() {
            command.push("--write-profile".into());
            command.push(crate::shell::posix_quote(write_profile).into_owned());
        }
        command.push("set".into());
        command.push(name.to_string());
        let command = command.join(" ");
        let command = match std::env::current_dir() {
            Ok(dir) => format!(
                "cd {} && {command}",
                crate::shell::posix_quote(&dir.to_string_lossy())
            ),
            Err(_) => command,
        };
        format!(
            "This MCP client can't open fnox's secure input page (it doesn't support URL-mode elicitation). Don't ask the user to paste '{name}' into the chat. Ask them to run this in their own terminal, where fnox prompts for the value with hidden input:\n\n    {command}\n\nThen call request_secret again with the same name and without replace. fnox will load the stored value without showing it to you."
        )
    }
}

use crate::redact::redactable;

/// Replace all occurrences of secret values in `text` with `[REDACTED]`.
///
/// Uses Aho-Corasick with leftmost-longest matching for single-pass replacement,
/// avoiding issues with sequential replacement (e.g., a short secret matching
/// inside an already-placed `[REDACTED]` marker).
///
/// Secrets shorter than `MIN_REDACT_LENGTH` or that are empty/whitespace-only
/// are skipped to avoid false positives. Values are trimmed before matching
/// so that trailing newlines (common when secrets are loaded from files) don't
/// prevent redaction of the core value in output.
fn redact_secrets(text: &str, secret_values: &[(String, String)]) -> Result<String, McpError> {
    let values: Vec<&str> = secret_values
        .iter()
        .filter_map(|(_, v)| redactable(v))
        .collect();

    if values.is_empty() {
        return Ok(text.to_string());
    }

    let ac = aho_corasick::AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(&values)
        .map_err(|e| {
            McpError::internal_error(
                format!(
                    "Failed to build redaction filter: {e}. Refusing to return unredacted output."
                ),
                None,
            )
        })?;

    Ok(ac.replace_all(text, &vec!["[REDACTED]"; values.len()]))
}

/// Manually implement ServerHandler instead of using #[tool_handler] so we can
/// filter the tool list based on mcp_config.tools at listing time (not just
/// at call time).
impl ServerHandler for FnoxMcpServer {
    fn get_info(&self) -> ServerConfig {
        let tools = self.mcp_config.tools();
        let has_get_secret = tools.contains(&McpTool::GetSecret);
        let has_exec = tools.contains(&McpTool::Exec);
        let has_request_secret = tools.contains(&McpTool::RequestSecret);
        let mut instructions = if has_get_secret && has_exec {
            "fnox MCP server — a session-scoped secret broker. \
             Use get_secret to retrieve individual secrets, \
             or exec to run commands with secrets injected as environment variables."
        } else if has_get_secret {
            "fnox MCP server — a session-scoped secret broker. \
             Use get_secret to retrieve individual secrets."
        } else if has_exec {
            "fnox MCP server — a session-scoped secret broker. \
             Use exec to run commands with secrets injected as environment variables."
        } else if has_request_secret {
            "fnox MCP server — a session-scoped secret broker."
        } else {
            "fnox MCP server — no tools are currently enabled."
        }
        .to_string();
        if has_request_secret {
            instructions.push_str(
                " When a task needs a secret that isn't set, call request_secret: \
                 the user enters it on a local fnox page and you never see the value. \
                 Never ask the user to paste a secret into the chat.",
            );
        }

        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("fnox-mcp", env!("CARGO_PKG_VERSION")))
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(instructions)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(self.list_tools_result())
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        let tools = self.mcp_config.tools();
        let enabled: Vec<&str> = tools.iter().map(|t| t.tool_name()).collect();
        if !enabled.contains(&name) {
            return None;
        }
        self.tool_router.get(name).cloned()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let tools = self.mcp_config.tools();
        let enabled: Vec<&str> = tools.iter().map(|t| t.tool_name()).collect();
        if !enabled.contains(&request.name.as_ref()) {
            return Err(McpError::invalid_request(
                format!(
                    "Tool '{}' is not enabled in this configuration",
                    request.name
                ),
                None,
            ));
        }
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_tools_includes_conservative_cache_hints() {
        let server = FnoxMcpServer::new(
            Config::default(),
            vec!["default".into()],
            McpConfig::default(),
            ResolveContext {
                config: "fnox.toml".into(),
                profile: vec!["default".into()],
                age_key_file: None,
                if_missing: None,
                no_defaults: false,
                non_interactive: true,
                no_daemon: true,
            },
            IndexMap::new(),
        );

        let result = server.list_tools_result();
        assert_eq!(result.ttl_ms, Some(0));
        assert_eq!(result.cache_scope, Some(CacheScope::Private));
    }

    #[test]
    fn terminal_fallback_quotes_profile_names() {
        let profile = vec!["my profile".to_string()];
        let server = FnoxMcpServer::new(
            Config::default(),
            profile.clone(),
            McpConfig::default(),
            ResolveContext {
                config: "fnox.toml".into(),
                profile,
                age_key_file: None,
                if_missing: None,
                no_defaults: false,
                non_interactive: true,
                no_daemon: true,
            },
            IndexMap::new(),
        )
        .with_write_target("fnox.toml".into(), Some("my profile".into()));

        let text = server.terminal_fallback("API_TOKEN");
        assert!(
            text.contains("fnox -P 'my profile' --write-profile 'my profile' set API_TOKEN"),
            "{text}"
        );
    }

    #[test]
    fn mcp_exec_command_scrubs_ambient_age_identity() {
        let mut cmd = tokio::process::Command::new("unused");
        scrub_age_identity(&mut cmd);

        let removed = cmd
            .as_std()
            .get_envs()
            .filter_map(|(key, value)| value.is_none().then_some(key.to_string_lossy()))
            .collect::<Vec<_>>();
        assert!(removed.iter().any(|key| key == "FNOX_AGE_KEY"));
        assert!(removed.iter().any(|key| key == "FNOX_AGE_KEY_FILE"));
        assert!(removed.iter().any(|key| key == "FNOX_ENPASS_PASSWORD"));
        assert!(removed.iter().any(|key| key == "ENPASS_PASSWORD"));
    }

    #[test]
    fn redact_replaces_secret_values() {
        let secrets = vec![
            ("API_KEY".into(), "sk-abc123".into()),
            ("DB_PASS".into(), "hunter2".into()),
        ];
        let input = "API_KEY=sk-abc123\nDB_PASS=hunter2\nOK=public";
        let result = redact_secrets(input, &secrets).unwrap();
        assert_eq!(result, "API_KEY=[REDACTED]\nDB_PASS=[REDACTED]\nOK=public");
    }

    #[test]
    fn redact_longest_match_wins() {
        let secrets = vec![
            ("SHORT".into(), "abc".into()),
            ("LONG".into(), "abcdef".into()),
        ];
        let input = "value is abcdef";
        let result = redact_secrets(input, &secrets).unwrap();
        assert_eq!(result, "value is [REDACTED]");
    }

    #[test]
    fn redact_skips_empty_and_short_secrets() {
        let secrets = vec![
            ("EMPTY".into(), "".into()),
            ("SPACES".into(), "   ".into()),
            ("SHORT".into(), "ab".into()),
            ("REAL".into(), "secret".into()),
        ];
        let input = "the secret has ab in it";
        let result = redact_secrets(input, &secrets).unwrap();
        assert_eq!(result, "the [REDACTED] has ab in it");
    }

    #[test]
    fn redact_no_secrets_returns_unchanged() {
        let input = "nothing to redact here";
        let result = redact_secrets(input, &[]).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn redact_multiple_occurrences() {
        let secrets = vec![("TOKEN".into(), "xyz789".into())];
        let input = "xyz789 and xyz789 again";
        let result = redact_secrets(input, &secrets).unwrap();
        assert_eq!(result, "[REDACTED] and [REDACTED] again");
    }

    #[test]
    fn redact_does_not_corrupt_markers() {
        // A secret that is a substring of "[REDACTED]" should not corrupt
        // already-placed markers (aho-corasick does single-pass replacement).
        let secrets = vec![
            ("LONG".into(), "sk-abc123".into()),
            ("OVERLAP".into(), "DACT".into()),
        ];
        let input = "sk-abc123 key";
        let result = redact_secrets(input, &secrets).unwrap();
        assert_eq!(result, "[REDACTED] key");
    }
}
