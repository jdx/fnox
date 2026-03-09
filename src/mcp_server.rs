use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars;
use rmcp::{ErrorData as McpError, ServerHandler};
use rmcp::{tool, tool_handler, tool_router};
use tokio::sync::RwLock;

use crate::config::{Config, McpConfig, SecretConfig};
use crate::secret_resolver::resolve_secrets_batch;

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
            tool_router: Self::tool_router(),
        }
    }

    /// Ensure all secrets are resolved and cached. First call resolves the
    /// entire batch (amortizes yubikey/SSO cost); subsequent calls are no-ops.
    async fn ensure_resolved(&self) -> Result<(), McpError> {
        // Fast path: already resolved
        if !self.cache.read().await.is_empty() {
            return Ok(());
        }

        let mut cache = self.cache.write().await;
        // Double-check after acquiring write lock
        if !cache.is_empty() {
            return Ok(());
        }

        let resolved = resolve_secrets_batch(&self.config, &self.profile, &self.profile_secrets)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to resolve secrets: {e}"), None)
            })?;

        for (key, value) in resolved {
            if let Some(v) = value {
                cache.insert(key, v);
            }
        }

        Ok(())
    }

    /// Retrieve a single secret by name.
    #[tool(description = "Get a secret value by name from the fnox configuration")]
    async fn get_secret(
        &self,
        Parameters(params): Parameters<GetSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        if !self.mcp_config.tools.contains(&"get_secret".to_string()) {
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
        if !self.mcp_config.tools.contains(&"exec".to_string()) {
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

        // Inject secrets as env vars — must NOT inherit stdio (would corrupt JSON-RPC)
        for (key, value) in cache.iter() {
            cmd.env(key, value);
        }

        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = cmd.output().await.map_err(|e| {
            McpError::internal_error(
                format!("Failed to execute command '{}': {e}", params.command[0]),
                None,
            )
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let mut text = String::new();
        if !stdout.is_empty() {
            text.push_str(&stdout);
        }
        if !stderr.is_empty() {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str("[stderr]\n");
            text.push_str(&stderr);
        }

        let exit_code = output.status.code().unwrap_or(-1);
        if !output.status.success() {
            text.push_str(&format!("\n[exit code: {exit_code}]"));
        }

        if text.is_empty() {
            text = format!("[exit code: {exit_code}]");
        }

        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

#[tool_handler]
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
}
