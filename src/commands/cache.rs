use crate::cache;
use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use clap::{Args, Subcommand};

/// Manage the auto-sync secret cache
#[derive(Args)]
pub struct CacheCommand {
    #[command(subcommand)]
    command: CacheSubcommand,
}

#[derive(Subcommand)]
pub enum CacheSubcommand {
    /// Clear the cache for the current project
    Clear(CacheClearCommand),

    /// Show cache status for the current project
    Status(CacheStatusCommand),
}

#[derive(Args)]
pub struct CacheClearCommand {}

#[derive(Args)]
pub struct CacheStatusCommand {}

impl CacheCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        match &self.command {
            CacheSubcommand::Clear(cmd) => cmd.run(cli, &config),
            CacheSubcommand::Status(cmd) => cmd.run(cli, &config),
        }
    }
}

impl CacheClearCommand {
    fn run(&self, cli: &Cli, config: &Config) -> Result<()> {
        let project_dir = crate::lease::project_dir_from_config(config, &cli.config);
        cache::invalidate_cache(&project_dir);
        println!("Cache cleared for {}", project_dir.display());
        Ok(())
    }
}

impl CacheStatusCommand {
    fn run(&self, cli: &Cli, config: &Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        let project_dir = crate::lease::project_dir_from_config(config, &cli.config);
        let report = cache::cache_report(config, &profile, &project_dir);

        println!("Cache Status");
        println!("============");
        println!();
        println!("  Enabled: {}", if report.enabled { "yes" } else { "no" });

        if let Some(ref ep) = report.encryption_provider {
            println!("  Encryption provider: {}", ep);
        }

        if report.plaintext_warning {
            println!("  WARNING: cache is storing secrets in plaintext (no encryption provider)");
        }

        if let Some(ref path) = report.cache_file {
            println!("  Cache file: {}", path.display());
            println!("  Cached secrets: {}", report.num_secrets);
            if let Some(age) = report.age_seconds {
                let mins = age / 60;
                let secs = age % 60;
                if mins > 0 {
                    println!("  Age: {}m {}s", mins, secs);
                } else {
                    println!("  Age: {}s", secs);
                }
            }
        } else {
            println!("  Cache file: (none)");
        }

        let settings = crate::settings::Settings::get();
        println!();
        println!("  TTL: {}", settings.cache_ttl);

        Ok(())
    }
}
