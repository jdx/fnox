use crate::commands::Cli;
use crate::config::Config;
use crate::daemon;
use crate::error::Result;
use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct DaemonCommand {
    #[command(subcommand)]
    command: DaemonSubcommand,
}

#[derive(Debug, Subcommand)]
enum DaemonSubcommand {
    /// Clear the daemon's in-memory cache
    Clear,
    /// Run the daemon server in the foreground
    #[command(hide = true)]
    Serve,
    /// Start the per-user daemon in the background
    Start,
    /// Show daemon status
    Status,
    /// Stop the daemon
    Stop,
}

impl DaemonCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        match self.command {
            DaemonSubcommand::Clear => {
                daemon::clear(cli).await?;
                println!("fnox daemon cache cleared");
                Ok(())
            }
            DaemonSubcommand::Serve => {
                let timeout = std::env::var("FNOX_DAEMON_IDLE_TIMEOUT")
                    .ok()
                    .unwrap_or_else(|| {
                        crate::config::DaemonConfig::DEFAULT_IDLE_TIMEOUT.to_string()
                    });
                let timeout = daemon::parse_duration(&timeout)?;
                daemon::serve(cli, timeout).await
            }
            DaemonSubcommand::Start => {
                let config = Config::load_smart(&cli.config).ok();
                if daemon::start_background(cli, config.as_ref()).await? {
                    println!("fnox daemon started");
                } else {
                    println!("fnox daemon already running");
                }
                Ok(())
            }
            DaemonSubcommand::Status => {
                match daemon::status(cli).await? {
                    Some((pid, cached_entries)) => {
                        println!("fnox daemon running");
                        println!("pid: {}", pid);
                        println!("cached_entries: {}", cached_entries);
                    }
                    None => println!("fnox daemon not running"),
                }
                Ok(())
            }
            DaemonSubcommand::Stop => {
                daemon::shutdown(cli).await?;
                println!("fnox daemon stopped");
                Ok(())
            }
        }
    }
}
