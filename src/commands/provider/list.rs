use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use clap::Args;

#[derive(Debug, Args)]
#[command(visible_aliases = ["ls"])]
pub struct ListCommand {
    /// Output provider names for shell completion (one per line)
    #[arg(long, hide = true)]
    pub complete: bool,
}

impl ListCommand {
    pub async fn run(&self, _cli: &Cli, config: Config) -> Result<()> {
        tracing::debug!("Listing providers");

        if config.providers.is_empty() {
            return Ok(());
        }

        // Always just output provider names, one per line
        let mut names: Vec<_> = config.providers.keys().collect();
        names.sort();
        for name in names {
            println!("{}", name);
        }

        Ok(())
    }
}
