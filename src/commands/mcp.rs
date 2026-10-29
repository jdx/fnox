use crate::commands::Cli;
use crate::config::{Config, McpTool};
use crate::error::Result;
use crate::mcp::FnoxMcpServer;
use crate::secret_session::SecretSession;
use crate::{env, error::FnoxError};
use rmcp::service::RunningService;
use rmcp::{RoleServer, ServiceExt};

/// Serve secrets to AI agents over the Model Context Protocol
///
/// Starts an MCP server on stdin and stdout for an agent client to launch. It
/// offers the `get_secret` and `exec` tools, limited by the `[mcp]` table:
/// `tools` chooses which tools are offered and `secrets` restricts which secrets
/// they can reach. Add `request_secret` to `tools` to let the agent ask you to
/// enter a missing secret on a local page. The server never prompts in the
/// terminal, so authenticate to your providers before starting the client.
///
/// Under `fnox proxy run`, `fnox mcp` relays to the proxy instead, which
/// serves the tools with placeholders rather than real values.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox mcp", header = "Start the server for the current project"),
    example("fnox -P staging mcp", header = "Serve another profile"),
    after_long_help = "See also:\n- MCP server: https://fnox.jdx.dev/guide/mcp"
)]
pub struct McpCommand;

impl McpCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        // MCP server must be non-interactive — provider stdin prompts would
        // corrupt the JSON-RPC stream on stdout.
        env::set_non_interactive(true);

        let profile = Config::get_profiles(cli.profile.as_slice());
        let mcp_config = config.mcp.clone().unwrap_or_default();

        // Warn about allowlist entries that don't match any configured secret
        let all_secrets = config.get_secrets(&profile)?;
        if let Some(ref allowlist) = mcp_config.secrets {
            if allowlist.is_empty() {
                tracing::warn!(
                    "mcp.secrets is set to an empty list — no secrets will be available to the MCP server"
                );
            }
            let allowed_set: std::collections::HashSet<&str> =
                allowlist.iter().map(|s| s.as_str()).collect();
            let providers = config.get_providers(&profile)?;
            let can_request = mcp_config.tools().contains(&McpTool::RequestSecret);
            for name in allowlist {
                if !all_secrets.contains_key(name) {
                    // request_secret may add it during the session
                    if can_request {
                        continue;
                    }
                    tracing::warn!(
                        "mcp.secrets allowlist contains '{name}' which is not a configured secret"
                    );
                    continue;
                }
                // Warn if this secret's provider depends on another fnox secret
                // that is not in the allowlist (would cause silent auth failure).
                if let Some(sc) = all_secrets.get(name)
                    && let Some(provider_name) = sc.provider()
                    && let Some(pc) = providers.get(provider_name)
                {
                    for dep in pc.env_dependencies() {
                        if all_secrets.contains_key(*dep) && !allowed_set.contains(*dep) {
                            tracing::warn!(
                                "mcp.secrets: '{name}' uses provider '{provider_name}' which \
                                 depends on '{dep}' — add '{dep}' to mcp.secrets or its provider \
                                 may fail to authenticate"
                            );
                        }
                    }
                }
            }
        }

        // Apply MCP secret allowlist (no-op if not set)
        let profile_secrets = mcp_config.filter_secrets(all_secrets);

        if mcp_config.exec_timeout_secs == Some(0) {
            return Err(FnoxError::Config(
                "mcp.exec_timeout_secs must be >= 1; use a large value to effectively disable the timeout".into(),
            ));
        }

        let session = SecretSession::new(
            config,
            profile,
            crate::daemon::ResolveContext::from_cli(cli),
            crate::daemon::Purpose::Mcp,
            profile_secrets,
        )
        .with_write_target(cli.config.clone(), cli.write_profile.clone());
        let server = FnoxMcpServer::new(std::sync::Arc::new(session), mcp_config);

        let service: RunningService<RoleServer, FnoxMcpServer> = server
            .serve(rmcp::transport::io::stdio())
            .await
            .map_err(|e| FnoxError::Config(format!("Failed to start MCP server: {e}")))?;

        service
            .waiting()
            .await
            .map_err(|e| FnoxError::Config(format!("MCP server error: {e}")))?;

        Ok(())
    }
}
