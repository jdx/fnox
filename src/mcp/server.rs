use std::sync::Arc;

use indexmap::IndexMap;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};

use crate::config::{McpConfig, McpTool, SecretConfig};
use crate::proxy::ProxyHandle;
use crate::secret_session::SecretSession;

/// The fnox MCP server — acts as a session-scoped secret broker.
///
/// Secrets are resolved on first access (may require yubikey/SSO) and cached
/// in memory for the session. `as_file = true` secrets are written to
/// ephemeral temp files scoped to each exec call.
#[derive(Clone)]
pub struct FnoxMcpServer {
    pub(super) session: Arc<SecretSession>,
    pub(super) mcp_config: Arc<McpConfig>,
    /// Set when the server runs inside `fnox proxy run`: the tools then hand
    /// out placeholders and the proxy injects real values
    pub(super) proxy: Option<ProxyHandle>,
    pub(super) tool_router: ToolRouter<FnoxMcpServer>,
}

impl FnoxMcpServer {
    pub fn new(session: Arc<SecretSession>, mcp_config: McpConfig) -> Self {
        Self {
            session,
            mcp_config: Arc::new(mcp_config),
            proxy: None,
            tool_router: Self::secret_tools() + Self::request_secret_tools(),
        }
    }

    /// Serve the tools from inside `fnox proxy run`. `get_secret` returns
    /// placeholders, `exec` isn't offered (the proxy runs outside any
    /// sandbox), and a value `request_secret` stores goes to the proxy.
    pub fn under_proxy(mut self, proxy: ProxyHandle) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// A tool as this server describes it: under the proxy, the tools hand
    /// out placeholders and there is no `exec`
    pub(super) fn describe(&self, mut tool: Tool) -> Tool {
        if self.proxy.is_none() {
            return tool;
        }
        let description = match tool.name.as_ref() {
            "get_secret" => {
                "Get a secret's placeholder by name, the environment variable that holds it, and the domains the proxy injects the real value into. Never returns the real value."
            }
            "request_secret" => {
                "Ask the user to enter a secret that isn't set yet, such as an API key or auth token. fnox shows the user a local page to type it into, stores it, and hands it to the proxy. You get back the secret's placeholder: send it where the secret goes, and the proxy injects the real value. Use this instead of asking the user to paste a secret into the chat."
            }
            _ => return tool,
        };
        tool.description = Some(description.into());
        tool
    }

    /// The tools this server offers
    pub(super) fn enabled_tools(&self) -> Vec<McpTool> {
        let mut tools = self.mcp_config.tools();
        if self.proxy.is_some() {
            tools.retain(|tool| *tool != McpTool::Exec);
        }
        tools
    }

    /// The secrets this session can reach
    pub(super) fn secrets(&self) -> Arc<IndexMap<String, SecretConfig>> {
        self.session.secrets()
    }

    /// as_file secrets are meant to be consumed as file paths via exec, not
    /// retrieved as raw content. Reject them to avoid leaking key material.
    pub(super) fn reject_as_file(&self, name: &str) -> Result<(), McpError> {
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

    pub(super) fn list_tools_result(&self) -> ListToolsResult {
        let all_tools = self.tool_router.list_all();
        let tools = self.enabled_tools();
        let enabled: Vec<&str> = tools.iter().map(|t| t.tool_name()).collect();
        let filtered = all_tools
            .into_iter()
            .filter(|t| enabled.contains(&t.name.as_ref()))
            .map(|t| self.describe(t))
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
    pub(super) async fn ensure_resolved(&self) -> Result<(), McpError> {
        self.session
            .resolve_batch_once(|sc| sc.env_mode().in_exec())
            .await
            .map_err(|e| McpError::internal_error(format!("Failed to resolve secrets: {e}"), None))
    }

    /// Resolve a single env=false secret on demand and cache it.
    /// Returns the cached value if already resolved, or None for absent secrets.
    pub(super) async fn resolve_single(&self, name: &str) -> Result<Option<String>, McpError> {
        self.session.resolve(name).await.map_err(|e| {
            McpError::internal_error(format!("Failed to resolve secret '{name}': {e}"), None)
        })
    }
}

/// Manually implement ServerHandler instead of using #[tool_handler] so we can
/// filter the tool list based on mcp_config.tools at listing time (not just
/// at call time).
impl ServerHandler for FnoxMcpServer {
    fn get_info(&self) -> ServerConfig {
        let tools = self.enabled_tools();
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
        if self.proxy.is_some() {
            instructions = "fnox MCP server inside fnox proxy run. Real secret values never reach you: \
                 send a secret's placeholder, from its environment variable, where the secret goes, \
                 and the proxy swaps in the real value for the API it belongs to."
                .to_string();
            if has_get_secret {
                instructions
                    .push_str(" get_secret tells you a secret's placeholder and where it works.");
            }
        }
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
        let tools = self.enabled_tools();
        let enabled: Vec<&str> = tools.iter().map(|t| t.tool_name()).collect();
        if !enabled.contains(&name) {
            return None;
        }
        self.tool_router
            .get(name)
            .cloned()
            .map(|t| self.describe(t))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let tools = self.enabled_tools();
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

/// A server with an empty config and no daemon, for tests
#[cfg(test)]
pub(super) fn test_server(profile: Vec<String>, write_profile: Option<String>) -> FnoxMcpServer {
    let context = crate::daemon::ResolveContext {
        config: "fnox.toml".into(),
        profile: profile.clone(),
        age_key_file: None,
        if_missing: None,
        no_defaults: false,
        non_interactive: true,
        no_daemon: true,
    };
    let session = SecretSession::new(
        crate::config::Config::default(),
        profile,
        context,
        crate::daemon::Purpose::Mcp,
        IndexMap::new(),
    )
    .with_write_target("fnox.toml".into(), write_profile);
    FnoxMcpServer::new(Arc::new(session), McpConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_the_proxy_tools_describe_placeholders() {
        let config = crate::config::ProxyConfig {
            rules: vec![crate::config::ProxyRule {
                secret: Some("API_TOKEN".into()),
                lease: None,
                credential: None,
                domain: "api.example.com".into(),
                env: None,
                header: None,
                query: None,
                methods: vec![],
                paths: vec![],
                placeholder: None,
            }],
            ..Default::default()
        };
        let plan = crate::proxy::ProxyPlan::new(&config, &IndexMap::new()).unwrap();
        let server = test_server(vec!["default".into()], None).under_proxy(plan.handle());
        let tools = server.list_tools_result().tools;
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert_eq!(names, ["get_secret"], "exec isn't offered under the proxy");
        let description = tools[0].description.as_deref().unwrap_or_default();
        assert!(description.contains("placeholder"), "{description}");
    }

    #[test]
    fn list_tools_includes_conservative_cache_hints() {
        let server = test_server(vec!["default".into()], None);

        let result = server.list_tools_result();
        assert_eq!(result.ttl_ms, Some(0));
        assert_eq!(result.cache_scope, Some(CacheScope::Private));
    }
}
