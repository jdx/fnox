use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};

/// Show the local access audit log
///
/// Prints the most recent entries of the log written when `[audit] enabled = true`
/// (or `FNOX_AUDIT=on`) is set: when each secret was read, by which command,
/// under which profile, and through which provider. Values are never recorded.
/// The log is a file the current user can write, so it is a record of fnox's
/// activity, not tamper-proof evidence.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox audit", header = "Show the last 20 reads"),
    example(
        "fnox audit --secret DATABASE_URL -n 5",
        header = "Show recent reads of one secret"
    ),
    example(
        "fnox audit --command mcp --json",
        header = "Show reads made through the MCP server as JSON lines"
    ),
    after_long_help = "See also:\n- Audit log: https://fnox.jdx.dev/guide/audit"
)]
pub struct AuditCommand {
    /// Only entries from this command, such as `exec`, `get`, `hook-env`, `mcp`, or `proxy`
    #[usage(short, long)]
    pub command: Option<String>,

    /// Number of entries to show, most recent last (default: 20)
    #[usage(short = 'n', long)]
    pub limit: Option<usize>,

    /// Only entries for this provider
    #[usage(short, long)]
    pub provider: Option<String>,

    /// Only entries for this secret name
    #[usage(short, long)]
    pub secret: Option<String>,

    /// Print entries as JSON lines
    #[usage(long)]
    pub json: bool,

    /// Print the log file path and exit
    #[usage(long)]
    pub path: bool,
}

impl AuditCommand {
    pub async fn run(&self, _cli: &Cli, config: Config) -> Result<()> {
        let path = fnox_core::audit::log_path(&config);
        if self.path {
            println!("{}", path.display());
            return Ok(());
        }
        let limit = self.limit.unwrap_or(20);
        let matched = fnox_core::audit::tail(&path, limit, |e| {
            self.secret.as_ref().is_none_or(|s| {
                &e.secret == s || e.request.as_ref().is_some_and(|r| r.injected.contains(s))
            }) && self.command.as_ref().is_none_or(|c| &e.command == c)
                && self
                    .provider
                    .as_ref()
                    .is_none_or(|p| e.provider.as_ref() == Some(p))
        })
        .map_err(|e| {
            FnoxError::Config(format!("Failed to read audit log {}: {e}", path.display()))
        })?;
        if matched.is_empty() && !self.json {
            if fnox_core::audit::is_enabled(&config) {
                eprintln!("No audit entries in {}", path.display());
            } else {
                eprintln!(
                    "No audit entries in {}. Auditing is off; set `[audit] enabled = true` or FNOX_AUDIT=on.",
                    path.display()
                );
            }
            return Ok(());
        }
        for e in matched {
            if self.json {
                println!(
                    "{}",
                    serde_json::to_string(&e).map_err(|e| FnoxError::Config(e.to_string()))?
                );
            } else if let Some(r) = &e.request {
                println!(
                    "{}  {:<9} {} {}{}  {}  profile={}",
                    e.ts,
                    e.command,
                    printable(&r.method),
                    printable(&r.domain),
                    if r.path == "-" {
                        String::new()
                    } else {
                        printable(&r.path)
                    },
                    match &r.refused {
                        Some(reason) => format!("refused: {}", printable(reason)),
                        None if r.injected.is_empty() => "injected=-".to_string(),
                        None => format!("injected={}", r.injected.join(",")),
                    },
                    e.profile.join(",")
                );
            } else {
                println!(
                    "{}  {:<9} {}  provider={}  profile={}{}",
                    e.ts,
                    e.command,
                    e.secret,
                    e.provider.as_deref().unwrap_or("-"),
                    e.profile.join(","),
                    if e.cached { "  (daemon cache)" } else { "" }
                );
            }
        }
        Ok(())
    }
}

/// Escapes control characters so a request a client crafted cannot move the
/// cursor or rewrite the terminal when the log is read. JSON output is
/// already escaped.
fn printable(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
