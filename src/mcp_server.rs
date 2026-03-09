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
    /// The command and arguments to execute (e.g. ["curl", "-H", "Authorization: Bearer $TOKEN", "https://api.example.com"])
    pub command: Vec<String>,
}

/// The fnox MCP server — acts as a session-scoped secret broker.
///
/// Secrets are resolved on first access (may require yubikey/SSO), cached in
/// memory for the session, and never persisted to disk.
#[derive(Clone)]
pub struct FnoxMcpServer {
    config: Arc<Config>,
    profile: Arc<String>,
    mcp_config: Arc<McpConfig>,
    profile_secrets: Arc<IndexMap<String, SecretConfig>>,
    cache: Arc<RwLock<HashMap<String, String>>>,
    /// Keeps temp files alive for as_file secrets across the session
    _temp_files: Arc<RwLock<Vec<tempfile::NamedTempFile>>>,
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
            _temp_files: Arc::new(RwLock::new(Vec::new())),
            resolved: Arc::new(OnceCell::new()),
            tool_router: Self::tool_router(),
        }
    }

    /// Ensure all secrets are resolved and cached. First call resolves the
    /// entire batch (amortizes yubikey/SSO cost); subsequent calls are no-ops.
    ///
    /// Respects `env = false` (skips injection) and `as_file = true` (writes
    /// to a temp file and stores the path instead of the raw value).
    async fn ensure_resolved(&self) -> Result<(), McpError> {
        let config = self.config.clone();
        let profile = self.profile.clone();
        let profile_secrets = self.profile_secrets.clone();
        let cache = self.cache.clone();
        let temp_files = self._temp_files.clone();

        self.resolved
            .get_or_try_init(|| async {
                let resolved = resolve_secrets_batch(&config, &profile, &profile_secrets)
                    .await
                    .map_err(|e| {
                        McpError::internal_error(format!("Failed to resolve secrets: {e}"), None)
                    })?;

                let mut cache = cache.write().await;
                let mut temp_files = temp_files.write().await;
                for (key, value) in resolved {
                    // Skip secrets marked env=false — they should only be
                    // accessible via `fnox get`, not injected into env.
                    if let Some(secret_config) = profile_secrets.get(&key)
                        && !secret_config.env
                    {
                        continue;
                    }

                    if let Some(v) = value {
                        // Handle as_file: write to temp file, store path
                        if let Some(secret_config) = profile_secrets.get(&key)
                            && secret_config.as_file
                        {
                            let temp_file =
                                create_ephemeral_secret_file(&key, &v).map_err(|e| {
                                    McpError::internal_error(
                                        format!(
                                            "Failed to create temp file for secret '{key}': {e}"
                                        ),
                                        None,
                                    )
                                })?;
                            let file_path = temp_file.path().to_string_lossy().to_string();
                            temp_files.push(temp_file);
                            cache.insert(key, file_path);
                            continue;
                        }
                        cache.insert(key, v);
                    }
                }

                Ok(())
            })
            .await?;

        Ok(())
    }

    /// Retrieve a single secret by name.
    #[tool(description = "Get a secret value by name from the fnox configuration")]
    async fn get_secret(
        &self,
        Parameters(params): Parameters<GetSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        if !self.mcp_config.tools.contains(&McpTool::GetSecret) {
            return Err(McpError::invalid_request(
                "Tool 'get_secret' is not enabled in this configuration",
                None,
            ));
        }

        self.ensure_resolved().await?;

        let cache = self.cache.read().await;
        match cache.get(&params.name) {
            Some(value) => Ok(CallToolResult::success(vec![Content::text(value.clone())])),
            None => {
                // Check if the secret exists in config but resolved to None
                if self.profile_secrets.contains_key(&params.name) {
                    Err(McpError::internal_error(
                        format!(
                            "Secret '{}' is configured but could not be resolved",
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
        if !self.mcp_config.tools.contains(&McpTool::Exec) {
            return Err(McpError::invalid_request(
                "Tool 'exec' is not enabled in this configuration",
                None,
            ));
        }

        if params.command.is_empty() {
            return Err(McpError::invalid_params("Command must not be empty", None));
        }

        self.ensure_resolved().await?;

        let cache = self.cache.read().await;

        let mut cmd = tokio::process::Command::new(&params.command[0]);
        if params.command.len() > 1 {
            cmd.args(&params.command[1..]);
        }

        // Inject cached secrets as env vars (already filtered for env/as_file)
        for (key, value) in cache.iter() {
            cmd.env(key, value);
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

        let timeout_secs = self
            .mcp_config
            .exec_timeout_secs
            .unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS);
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), cmd.output())
                .await
                .map_err(|_| {
                    McpError::internal_error(
                        format!(
                            "Command '{}' timed out after {timeout_secs}s",
                            params.command[0]
                        ),
                        None,
                    )
                })?
                .map_err(|e| {
                    McpError::internal_error(
                        format!("Failed to execute command '{}': {e}", params.command[0]),
                        None,
                    )
                })?;

        let stdout_raw = &output.stdout;
        let stderr_raw = &output.stderr;
        let total_bytes = stdout_raw.len() + stderr_raw.len();
        let truncated = total_bytes > MAX_OUTPUT_BYTES;

        // Cap output to prevent unbounded memory usage in JSON-RPC response
        let stdout = String::from_utf8_lossy(&stdout_raw[..stdout_raw.len().min(MAX_OUTPUT_BYTES)]);
        let stderr_budget = MAX_OUTPUT_BYTES.saturating_sub(stdout_raw.len().min(MAX_OUTPUT_BYTES));
        let stderr = String::from_utf8_lossy(&stderr_raw[..stderr_raw.len().min(stderr_budget)]);

        let mut parts = Vec::new();
        if !stdout.is_empty() {
            parts.push(stdout.to_string());
        }
        if !stderr.is_empty() {
            parts.push(format!("[stderr]\n{stderr}"));
        }

        let exit_code = output.status.code().unwrap_or(-1);
        if !output.status.success() || parts.is_empty() {
            parts.push(format!("[exit code: {exit_code}]"));
        }
        if truncated {
            parts.push(format!(
                "[output truncated: {total_bytes} bytes exceeded {MAX_OUTPUT_BYTES} byte limit]"
            ));
        }

        let text = parts.join("\n");
        if output.status.success() {
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
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("fnox-mcp", env!("CARGO_PKG_VERSION")))
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "fnox MCP server — a session-scoped secret broker. \
                 Use get_secret to retrieve individual secrets, \
                 or exec to run commands with secrets injected as environment variables."
                    .to_string(),
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let all_tools = self.tool_router.list_all();
        let enabled: Vec<&str> = self
            .mcp_config
            .tools
            .iter()
            .map(|t| t.tool_name())
            .collect();
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
        let enabled: Vec<&str> = self
            .mcp_config
            .tools
            .iter()
            .map(|t| t.tool_name())
            .collect();
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
