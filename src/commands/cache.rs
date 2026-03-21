use crate::cache;
use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use crate::secret_resolver::resolve_secrets_batch;
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

    /// Internal: refresh cache in the background (not for direct use)
    #[command(hide = true)]
    Refresh(CacheRefreshCommand),

    /// Show cache status for the current project
    Status(CacheStatusCommand),
}

#[derive(Args)]
pub struct CacheClearCommand {}

#[derive(Args)]
pub struct CacheStatusCommand {}

#[derive(Args)]
pub struct CacheRefreshCommand {}

impl CacheCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        match &self.command {
            CacheSubcommand::Clear(cmd) => cmd.run(cli, &config),
            CacheSubcommand::Status(cmd) => cmd.run(cli, &config),
            CacheSubcommand::Refresh(cmd) => cmd.run(cli, config).await,
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
        println!("  Soft TTL: {}", settings.cache_soft_ttl);
        println!("  Hard TTL: {}", settings.cache_hard_ttl);

        Ok(())
    }
}

impl CacheRefreshCommand {
    /// Internal command called by the background refresh process.
    /// Not intended for direct user invocation.
    async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());

        // Get the project dir from env var set by spawn_background_refresh
        let project_dir = std::env::var("__FNOX_CACHE_PROJECT_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| crate::lease::project_dir_from_config(&config, &cli.config));

        let refreshing_path = std::env::var("__FNOX_CACHE_REFRESHING_PATH")
            .map(std::path::PathBuf::from)
            .ok();

        // Clean up refreshing lock on exit (in all paths)
        let _guard = RefreshingGuard {
            path: refreshing_path,
        };

        let encryption_provider = match cache::is_cache_enabled(&config, &profile) {
            Some(ep) => ep,
            None => return Ok(()),
        };

        let secrets = config.get_secrets(&profile)?;
        let resolved = resolve_secrets_batch(&config, &profile, &secrets).await?;
        let cache_key = cache::compute_cache_key(&project_dir, &profile);

        cache::write_cache(
            &config,
            &profile,
            &project_dir,
            &cache_key,
            &encryption_provider,
            &resolved,
        )
        .await?;

        Ok(())
    }
}

/// RAII guard that removes the `.refreshing` lock file on drop.
struct RefreshingGuard {
    path: Option<std::path::PathBuf>,
}

impl Drop for RefreshingGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}
