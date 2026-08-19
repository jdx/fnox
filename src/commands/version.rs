use crate::commands::Cli;
use crate::error::Result;
use clap::Parser;

#[derive(usage_derive::Cli)]
#[usage(alias("v"))]
pub struct VersionCommand;

impl VersionCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        Ok(())
    }
}
