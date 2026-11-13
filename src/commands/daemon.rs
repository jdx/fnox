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
    example(
        "FNOX_DAEMON=on fnox get DATABASE_URL",
        header = "Use the daemon for one command"
    ),
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
        example(
            "fnox daemon clear API_TOKEN DB_PASSWORD",
            header = "Evict two secrets"
        ),
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
    /// it is not running. With `--verbose`, also lists each cached entry with its
    /// age and the time left on its `cache_ttl` and `max_cache_ttl`; values are
    /// never shown.
    #[usage(
        example("fnox daemon status", header = "Show daemon status"),
        example(
            "fnox daemon status --verbose",
            header = "List cached entries and the time left on their TTLs"
        ),
        example(
            "fnox daemon status --json",
            header = "Print the status and cached entries as JSON"
        ),
        after_long_help = "See also:\n- Daemon: https://fnox.jdx.dev/guide/daemon"
    )]
    Status {
        /// List each cached entry (key, profile, purpose, age, and TTL time
        /// left) without its value
        #[usage(short, long)]
        verbose: bool,

        /// Print the status and cached entries as JSON; values are never included
        #[usage(long)]
        json: bool,
    },
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
    pub(crate) fn serves_connections(&self) -> bool {
        matches!(self.command, DaemonSubcommand::Serve)
    }

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
            DaemonSubcommand::Status { verbose, json } => {
                let status = daemon::status(cli).await?;
                if *json {
                    let value = match &status {
                        Some(status) => serde_json::json!({
                            "running": true,
                            "pid": status.pid,
                            "cached_entries": status.cached_entries,
                            "entries": status.entries,
                        }),
                        None => serde_json::json!({ "running": false }),
                    };
                    println!("{}", serde_json::to_string_pretty(&value)?);
                    return Ok(());
                }
                match status {
                    Some(status) => {
                        println!("fnox daemon running");
                        println!("pid: {}", status.pid);
                        println!("cached_entries: {}", status.cached_entries);
                        if *verbose && !status.entries.is_empty() {
                            println!();
                            print!("{}", daemon::format_entries(&status.entries));
                        }
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
