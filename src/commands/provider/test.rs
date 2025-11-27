use crate::commands::Cli;
use crate::config::Config;
use crate::config_resolver::ResolutionContext;
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

        let providers = config.get_providers(&profile);
        let provider_config = providers
            .get(&self.provider)
            .ok_or_else(|| FnoxError::Config(format!("Provider '{}' not found", self.provider)))?;

        // Create the provider instance (resolving any secret refs)
        let mut ctx = ResolutionContext::new(&config, &profile);
        let provider = provider_config.create_provider(&mut ctx).await?;

        // Test the connection
        provider.test_connection().await?;

        println!("✓ Provider '{}' connection successful", self.provider);
        Ok(())
    }
}
