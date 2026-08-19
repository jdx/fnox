use crate::commands::Cli;
use crate::error::Result;

#[derive(usage_derive::Args)]
#[usage(hide)]
pub struct UsageCommand {}

impl UsageCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let spec: usage::Spec = cmd.into();

        let min_version = r#"min_usage_version "1.3""#;
        let extra = include_str!("../assets/fnox-extras.usage.kdl").trim();

        println!("{min_version}\n{}\n{extra}", spec.to_string().trim());
        Ok(())
    }
}
