use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use crate::mcp_server::FnoxMcpServer;
use crate::{env, error::FnoxError};
use clap::Args;
use rmcp::service::RunningService;
use rmcp::{RoleServer, ServiceExt};

#[derive(Debug, Args)]
pub struct McpCommand {}

impl McpCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        // MCP server must be non-interactive — provider stdin prompts would
        // corrupt the JSON-RPC stream on stdout.
        env::set_non_interactive(true);

        let profile = Config::get_profile(cli.profile.as_deref());
        let profile_secrets = config.get_secrets(&profile)?;
        let mcp_config = config.mcp.clone().unwrap_or_default();

        if mcp_config.exec_timeout_secs == Some(0) {
            return Err(FnoxError::Config(
                "mcp.exec_timeout_secs must be >= 1; use a large value to effectively disable the timeout".into(),
            ));
        }

        let server = FnoxMcpServer::new(config, profile, mcp_config, profile_secrets);

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
