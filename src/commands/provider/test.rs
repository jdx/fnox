use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use clap::Args;

#[derive(Debug, Args)]
#[command(visible_aliases = ["t"])]
pub struct TestCommand {
    /// Provider name
    pub provider: String,
}

impl TestCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Testing provider '{}'", self.provider);

        let provider_config = config
            .providers
            .get(&self.provider)
            .ok_or_else(|| FnoxError::Config(format!("Provider '{}' not found", self.provider)))?;

        // Create the provider instance (resolving any secret refs in config)
        let provider = crate::providers::get_provider_resolved(
            &config,
            &profile,
            &self.provider,
            provider_config,
        )
        .await?;

        // Test the connection
        provider.test_connection().await?;

        println!("✓ Provider '{}' connection successful", self.provider);
        Ok(())
    }
}
