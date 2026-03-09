use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars;
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use rmcp::{tool, tool_router};
use tokio::sync::{OnceCell, RwLock};

use crate::config::{Config, McpConfig, McpTool, SecretConfig};
use crate::secret_resolver::resolve_secrets_batch;
use crate::temp_file_secrets::create_ephemeral_secret_file;

/// Maximum output size (1 MiB) to prevent unbounded memory usage
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Default execution timeout (5 minutes)
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 300;

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

/// The fnox MCP server — acts as a session-scoped secret broker.
///
/// Secrets are resolved on first access (may require yubikey/SSO) and cached
/// in memory for the session. `as_file = true` secrets are written to
/// ephemeral temp files scoped to each exec call.
#[derive(Clone)]
pub struct FnoxMcpServer {
    config: Arc<Config>,
    profile: Arc<String>,
    mcp_config: Arc<McpConfig>,
    profile_secrets: Arc<IndexMap<String, SecretConfig>>,
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
        profile: String,
        mcp_config: McpConfig,
        profile_secrets: IndexMap<String, SecretConfig>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            profile: Arc::new(profile),
            mcp_config: Arc::new(mcp_config),
            profile_secrets: Arc::new(profile_secrets),
            cache: Arc::new(RwLock::new(HashMap::new())),
            resolved: Arc::new(OnceCell::new()),
            tool_router: Self::tool_router(),
        }
    }

    /// Ensure env=true secrets are resolved and cached. First call resolves
    /// the batch (amortizes yubikey/SSO cost); subsequent calls are no-ops.
    ///
    /// env=false secrets are NOT resolved here — they are more sensitive and
    /// resolved on-demand by `get_secret` to avoid unnecessary auth prompts.
    async fn ensure_resolved(&self) -> Result<(), McpError> {
        let config = self.config.clone();
        let profile = self.profile.clone();
        let profile_secrets = self.profile_secrets.clone();
        let cache = self.cache.clone();

        self.resolved
            .get_or_try_init(|| async {
                // Only batch-resolve env=true secrets; env=false are deferred
                let env_secrets: IndexMap<String, SecretConfig> = profile_secrets
                    .iter()
                    .filter(|(_, sc)| sc.env)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();

                let resolved = resolve_secrets_batch(&config, &profile, &env_secrets)
                    .await
                    .map_err(|e| {
                        McpError::internal_error(format!("Failed to resolve secrets: {e}"), None)
                    })?;

                let mut cache = cache.write().await;
                for (key, value) in resolved {
                    cache.insert(key, value);
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

        let secret_config = match self.profile_secrets.get(name) {
            Some(sc) => sc,
            None => return Ok(None),
        };

        // Build a single-entry map for resolve_secrets_batch
        let single: IndexMap<String, SecretConfig> = [(name.to_string(), secret_config.clone())]
            .into_iter()
            .collect();

        let resolved = resolve_secrets_batch(&self.config, &self.profile, &single)
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
    /// env=true secrets are resolved eagerly in the first batch. env=false
    /// secrets are resolved on-demand here (may trigger auth) and cached for
    /// subsequent calls.
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

        // as_file secrets are meant to be consumed as file paths via exec, not
        // retrieved as raw content. Reject them to avoid leaking key material.
        if let Some(sc) = self.profile_secrets.get(&params.name)
            && sc.as_file
        {
            return Err(McpError::invalid_request(
                format!(
                    "Secret '{}' is configured with as_file=true and can only be used via the exec tool",
                    params.name
                ),
                None,
            ));
        }

        // Ensure env=true secrets are batch-resolved
        self.ensure_resolved().await?;

        // Check cache (covers env=true secrets and previously resolved env=false).
        // Some(Some(v)) = present, Some(None) = known absent, None = not yet resolved.
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&params.name) {
                return match cached {
                    Some(value) => Ok(CallToolResult::success(vec![Content::text(value.clone())])),
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
        if let Some(secret_config) = self.profile_secrets.get(&params.name) {
            // env=false secrets are deferred; try on-demand resolution
            if !secret_config.env {
                return match self.resolve_single(&params.name).await? {
                    Some(value) => Ok(CallToolResult::success(vec![Content::text(value)])),
                    None => Err(McpError::invalid_request(
                        format!(
                            "Secret '{}' has no value (it may be optional and absent)",
                            params.name
                        ),
                        None,
                    )),
                };
            }
            // env=true but not in cache — should not happen after ensure_resolved,
            // but handle gracefully
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

        // Snapshot env vars from cache, filtering out env=false and absent secrets.
        // This releases the read lock before the potentially long subprocess.
        let env_vars: Vec<(String, String)> = {
            let cache = self.cache.read().await;
            cache
                .iter()
                .filter(|(key, _)| {
                    self.profile_secrets
                        .get(key.as_str())
                        .is_none_or(|sc| sc.env)
                })
                .filter_map(|(k, v)| v.as_ref().map(|val| (k.clone(), val.clone())))
                .collect()
        };

        // For as_file secrets, write raw values to temp files and inject the
        // file path as the env var. Temp files are kept alive until the
        // subprocess completes (held in _exec_temp_files).
        let mut _exec_temp_files = Vec::new();
        let mut cmd = tokio::process::Command::new(&params.command[0]);
        if params.command.len() > 1 {
            cmd.args(&params.command[1..]);
        }

        // Inject filtered secrets as env vars, converting as_file to temp paths
        for (key, value) in &env_vars {
            if let Some(sc) = self.profile_secrets.get(key.as_str())
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
        for (key, secret_config) in self.profile_secrets.iter() {
            if !secret_config.env {
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
            let per_stream_limit = (MAX_OUTPUT_BYTES / 2) + 1;

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

        let total_collected = stdout_buf.len() + stderr_buf.len();
        let truncated = total_collected > MAX_OUTPUT_BYTES;

        let stdout = String::from_utf8_lossy(&stdout_buf[..stdout_buf.len().min(MAX_OUTPUT_BYTES)]);
        let stderr_cap = MAX_OUTPUT_BYTES.saturating_sub(stdout_buf.len().min(MAX_OUTPUT_BYTES));
        let stderr = String::from_utf8_lossy(&stderr_buf[..stderr_buf.len().min(stderr_cap)]);

        let mut parts = Vec::new();
        if !stdout.is_empty() {
            parts.push(stdout.to_string());
        }
        if !stderr.is_empty() {
            parts.push(format!("[stderr]\n{stderr}"));
        }

        let exit_code = status.code().unwrap_or(-1);
        if !status.success() || parts.is_empty() {
            parts.push(format!("[exit code: {exit_code}]"));
        }
        if truncated {
            parts.push(format!(
                "[output truncated: {total_collected} bytes exceeded {MAX_OUTPUT_BYTES} byte limit]"
            ));
        }

        let text = parts.join("\n");
        if status.success() {
            Ok(CallToolResult::success(vec![Content::text(text)]))
        } else {
            Ok(CallToolResult::error(vec![Content::text(text)]))
        }
    }
}

/// Manually implement ServerHandler instead of using #[tool_handler] so we can
/// filter the tool list based on mcp_config.tools at listing time (not just
/// at call time).
impl ServerHandler for FnoxMcpServer {
    fn get_info(&self) -> ServerInfo {
        let tools = self.mcp_config.tools();
        let has_get_secret = tools.contains(&McpTool::GetSecret);
        let has_exec = tools.contains(&McpTool::Exec);
        let instructions = if has_get_secret && has_exec {
            "fnox MCP server — a session-scoped secret broker. \
             Use get_secret to retrieve individual secrets, \
             or exec to run commands with secrets injected as environment variables."
        } else if has_get_secret {
            "fnox MCP server — a session-scoped secret broker. \
             Use get_secret to retrieve individual secrets."
        } else if has_exec {
            "fnox MCP server — a session-scoped secret broker. \
             Use exec to run commands with secrets injected as environment variables."
        } else {
            "fnox MCP server — no tools are currently enabled."
        };

        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("fnox-mcp", env!("CARGO_PKG_VERSION")))
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(instructions.to_string())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let all_tools = self.tool_router.list_all();
        let tools = self.mcp_config.tools();
        let enabled: Vec<&str> = tools.iter().map(|t| t.tool_name()).collect();
        let filtered = all_tools
            .into_iter()
            .filter(|t| enabled.contains(&t.name.as_ref()))
            .collect();
        Ok(ListToolsResult {
            tools: filtered,
            meta: None,
            next_cursor: None,
        })
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
    ) -> Result<CallToolResult, McpError> {
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }
}
