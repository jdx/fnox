use crate::commands::Cli;
use crate::error::Result;

/// Print the fnox version
///
/// Prints `fnox` followed by the version number. Include it when you report a
/// bug.
#[derive(usage_rs::Args)]
#[usage(alias("v"))]
#[usage(
    example("fnox version", header = "Print the version"),
    after_long_help = "See also:\n- Troubleshooting: https://fnox.jdx.dev/guide/troubleshooting"
)]
pub struct VersionCommand;

impl VersionCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        Ok(())
    }
}
