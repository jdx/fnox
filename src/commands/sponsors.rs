use crate::commands::Cli;
use crate::error::Result;

#[derive(clap::Args)]
pub struct SponsorsCommand {}

impl SponsorsCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        println!(
            "fnox and the jdx.dev open source tools are sponsored by:\n\n  entire.io - https://entire.io\n  37signals - https://37signals.com\n\nView all sponsors: https://jdx.dev/sponsors.html"
        );
        Ok(())
    }
}
