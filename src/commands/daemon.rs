use crate::commands::Cli;
use crate::config::Config;
use crate::daemon;
use crate::error::Result;

/// Manage the per-user daemon that caches resolved secrets
///
/// The daemon keeps resolved values in memory, so repeated reads by `get`,
/// `exec`, and the shell hook skip the provider. Commands use it only when
/// `[daemon] enabled = true` is set in the config or `FNOX_DAEMON=on` is in the
/// environment; it then starts on demand. `--no-daemon` bypasses it for one
/// command.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox daemon status", header = "Check whether the daemon is running"),
    example("FNOX_DAEMON=on fnox get DATABASE_URL", header = "Use the daemon for one command"),
    after_long_help = "See also:\n- Daemon: https://fnox.jdx.dev/guide/daemon"
)]
pub struct DaemonCommand {
    #[usage(subcommand)]
    command: DaemonSubcommand,
}

#[derive(Debug, usage_rs::Subcommands)]
enum DaemonSubcommand {
    /// Evict cached values from running daemons
    ///
    /// With no KEYS, clears each running daemon's whole cache. With KEYS, evicts
    /// only those secrets and keeps the rest. Run it after changing a value at its
    /// provider. Encrypted `fnox sync` caches in config files are not affected.
    #[usage(
        example("fnox daemon clear", header = "Clear the whole cache"),
        example("fnox daemon clear API_TOKEN DB_PASSWORD", header = "Evict two secrets"),
        after_long_help = "See also:\n- Daemon: https://fnox.jdx.dev/guide/daemon"
    )]
    Clear {
        /// Secrets to evict (default: the whole cache)
        keys: Vec<String>,
    },
    /// Run the daemon server in the foreground
    #[usage(hide)]
    Serve,
    /// Start the daemon in the background
    ///
    /// Starts the per-user daemon unless it is already running. Commands use it
    /// only while it is enabled with `[daemon] enabled = true` or `FNOX_DAEMON=on`.
    #[usage(
        example("fnox daemon start", header = "Start the daemon"),
        after_long_help = "See also:\n- Daemon: https://fnox.jdx.dev/guide/daemon"
    )]
    Start,
    /// Show whether the daemon is running
    ///
    /// Prints the daemon's process ID and the number of cached entries, or that
    /// it is not running.
    #[usage(
        example("fnox daemon status", header = "Show daemon status"),
        after_long_help = "See also:\n- Daemon: https://fnox.jdx.dev/guide/daemon"
    )]
    Status,
    /// Stop the daemon and discard its cache
    ///
    /// While the daemon is still enabled, the next command that reads a secret
    /// starts it again.
    #[usage(
        example("fnox daemon stop", header = "Stop the daemon"),
        after_long_help = "See also:\n- Daemon: https://fnox.jdx.dev/guide/daemon"
    )]
    Stop,
}

impl DaemonCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        match &self.command {
            DaemonSubcommand::Clear { keys } => {
                daemon::clear(cli, keys).await?;
                if keys.is_empty() {
                    println!("fnox daemon cache cleared");
                } else {
                    println!("fnox daemon cache cleared for {}", keys.join(", "));
                }
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
