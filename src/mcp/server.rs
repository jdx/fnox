use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use indexmap::IndexMap;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::sync::{OnceCell, RwLock};

use crate::config::{self, Config, McpConfig, McpTool, SecretConfig};
use crate::daemon::{Purpose, ResolveContext};

/// The fnox MCP server — acts as a session-scoped secret broker.
///
/// Secrets are resolved on first access (may require yubikey/SSO) and cached
/// in memory for the session. `as_file = true` secrets are written to
/// ephemeral temp files scoped to each exec call.
#[derive(Clone)]
pub struct FnoxMcpServer {
    pub(super) config: Arc<Config>,
    pub(super) profile: Arc<Vec<String>>,
    pub(super) mcp_config: Arc<McpConfig>,
    pub(super) daemon_context: Arc<ResolveContext>,
    /// Replaced, not mutated, when request_secret stores a new secret
    pub(super) profile_secrets: Arc<std::sync::RwLock<Arc<IndexMap<String, SecretConfig>>>>,
    /// `--config` value, for finding the file request_secret writes to
    pub(super) config_path: Arc<PathBuf>,
    /// `--write-profile` value, for request_secret
    pub(super) write_profile: Arc<Option<String>>,
    /// Held while request_secret rechecks and stores a value, so two pages
    /// can't both pass the recheck and overwrite each other
    pub(super) store_lock: Arc<tokio::sync::Mutex<()>>,
    /// Held while a name sent to the terminal is reloaded and while a stored
    /// value is read back, so one can't drop a value the other just loaded.
    /// Taken after `store_lock` when both are held.
    pub(super) reload_lock: Arc<tokio::sync::Mutex<()>>,
    /// Names request_secret sent to `fnox set` in the terminal; their next
    /// check reloads the value instead of trusting the cache
    pub(super) sent_to_terminal: Arc<std::sync::Mutex<HashSet<String>>>,
    /// Resolved secret values (raw). None means "resolved but absent".
    /// as_file conversion happens at exec time.
    pub(super) cache: Arc<RwLock<HashMap<String, Option<String>>>>,
    /// Tracks whether secrets have been resolved (separate from cache emptiness,
    /// since all secrets may resolve to None for optional/absent secrets).
    pub(super) resolved: Arc<OnceCell<()>>,
    pub(super) tool_router: ToolRouter<FnoxMcpServer>,
}

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
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            sent_to_terminal: Arc::new(std::sync::Mutex::new(HashSet::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            resolved: Arc::new(OnceCell::new()),
            tool_router: Self::secret_tools() + Self::request_secret_tools(),
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
    pub(super) fn secrets(&self) -> Arc<IndexMap<String, SecretConfig>> {
        self.profile_secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
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

    /// Make a secret stored during this session available to the tools
    pub(super) async fn add_secret(&self, name: &str, secret: SecretConfig, value: String) {
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

    pub(super) fn list_tools_result(&self) -> ListToolsResult {
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
    pub(super) async fn ensure_resolved(&self) -> Result<(), McpError> {
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
    pub(super) async fn resolve_single(&self, name: &str) -> Result<Option<String>, McpError> {
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
}
