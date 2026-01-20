use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;

#[derive(clap::Args)]
#[command(hide = true)]
pub struct SchemaCommand {}

impl SchemaCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        let schema = schemars::schema_for!(Config);
        let json = serde_json::to_string_pretty(&schema)?;
        println!("{json}");
        Ok(())
    }
}
