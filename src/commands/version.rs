use crate::commands::Cli;
use crate::error::Result;

#[derive(usage_rs::Args)]
#[usage(alias("v"))]
pub struct VersionCommand {}

impl VersionCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        Ok(())
    }
}
