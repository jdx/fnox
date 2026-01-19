use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use clap::Args;

#[derive(Debug, Args)]
#[command(visible_aliases = ["t"])]
pub struct TestCommand {
    /// Provider name (optional when using --all)
    pub provider: Option<String>,

    /// Test all configured providers
    #[arg(short = 'a', long)]
    pub all: bool,
}

impl TestCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());

        if self.all {
            self.test_all_providers(cli, &config, &profile).await
        } else if let Some(ref provider_name) = self.provider {
            self.test_single_provider(&config, &profile, provider_name)
                .await
        } else {
            Err(FnoxError::Config(
                "Please specify a provider name or use --all to test all providers".to_string(),
            ))?
        }
    }

    async fn test_single_provider(
        &self,
        config: &Config,
        profile: &str,
        provider_name: &str,
    ) -> Result<()> {
        tracing::debug!("Testing provider '{}'", provider_name);

        let provider_config = config
            .providers
            .get(provider_name)
            .ok_or_else(|| FnoxError::Config(format!("Provider '{}' not found", provider_name)))?;

        // Create the provider instance (resolving any secret refs in config)
        let provider = crate::providers::get_provider_resolved(
            config,
            profile,
            provider_name,
            provider_config,
        )
        .await?;

        // Test the connection
        provider.test_connection().await?;

        let check = console::style("✓").green();
        let styled_provider = console::style(provider_name).cyan();
        println!("{check} Provider {styled_provider} connection successful");
        Ok(())
    }

    async fn test_all_providers(&self, cli: &Cli, config: &Config, profile: &str) -> Result<()> {
        let providers = config.get_providers(profile);

        if providers.is_empty() {
            println!("No providers configured");
            return Ok(());
        }

        println!(
            "Testing {} provider{}...\n",
            providers.len(),
            if providers.len() == 1 { "" } else { "s" }
        );

        let mut passed = 0;
        let mut failed = 0;
        let mut errors: Vec<(String, String)> = Vec::new();

        for (provider_name, provider_config) in providers {
            let styled_provider = console::style(&provider_name).cyan();
            print!("  {} ", styled_provider);

            match crate::providers::get_provider_resolved(
                config,
                profile,
                &provider_name,
                &provider_config,
            )
            .await
            {
                Ok(provider) => match provider.test_connection().await {
                    Ok(()) => {
                        let check = console::style("✓").green();
                        println!("{check}");
                        passed += 1;
                    }
                    Err(e) => {
                        let x = console::style("✗").red();
                        println!("{x}");
                        errors.push((provider_name.clone(), e.to_string()));
                        failed += 1;
                    }
                },
                Err(e) => {
                    let x = console::style("✗").red();
                    println!("{x}");
                    errors.push((provider_name.clone(), e.to_string()));
                    failed += 1;
                }
            }
        }

        println!();

        // Print summary
        if failed == 0 {
            let check = console::style("✓").green();
            println!(
                "{check} All {} provider{} passed",
                passed,
                if passed == 1 { "" } else { "s" }
            );
        } else {
            // Show errors
            if cli.verbose {
                println!("Errors:");
                for (provider_name, error) in &errors {
                    let styled_provider = console::style(provider_name).cyan();
                    let styled_error = console::style(error).red();
                    println!("  {styled_provider}: {styled_error}");
                }
                println!();
            }

            let x = console::style("✗").red();
            let styled_passed = console::style(passed).green();
            let styled_failed = console::style(failed).red();
            println!("{x} {styled_passed} passed, {styled_failed} failed");

            if !cli.verbose && !errors.is_empty() {
                println!(
                    "{}",
                    console::style("  Run with --verbose to see error details").dim()
                );
            }

            return Err(FnoxError::Config(format!(
                "{} provider{} failed",
                failed,
                if failed == 1 { "" } else { "s" }
            )))?;
        }

        Ok(())
    }
}
