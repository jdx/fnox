use crate::commands::Cli;
use crate::error::Result;

/// Show the companies that sponsor fnox
///
/// Prints the companies sponsoring fnox and the jdx.dev open source tools, with
/// a link to the full list.
#[derive(usage_rs::Args)]
#[usage(
    example("fnox sponsors", header = "Show sponsors"),
    after_long_help = "See also:\n- All sponsors: https://jdx.dev/sponsors.html"
)]
pub struct SponsorsCommand;

impl SponsorsCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        println!(
            "fnox and the jdx.dev open source tools are sponsored by:\n\n  entire.io - https://entire.io\n  Omacom Foundation - https://omarchy.org/patrons/\n\nView all sponsors: https://jdx.dev/sponsors.html"
        );
        Ok(())
    }
}
