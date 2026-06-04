use crate::commands::Cli;
use crate::error::Result;

#[derive(clap::Args)]
pub struct SponsorsCommand {}

impl SponsorsCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        println!(
            "fnox and the en.dev project family are sponsored by:\n\n  37signals - https://37signals.com\n\nView all sponsors: https://en.dev/sponsors.html"
        );
        Ok(())
    }
}
