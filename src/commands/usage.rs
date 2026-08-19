use crate::commands::Cli;
use crate::error::Result;

#[derive(usage_rs::Args)]
pub struct UsageCommand {}

impl UsageCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        let min_version = r#"min_usage_version "1.3""#;
        let extra = include_str!("../assets/fnox-extras.usage.kdl").trim();

        println!("{min_version}\n{}\n{extra}", Cli::to_kdl().trim());
        Ok(())
    }
}
