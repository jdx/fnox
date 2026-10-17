use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;

/// List the providers configured for the active profile
///
/// Prints each provider name, sorted, one per line.
#[derive(Debug, usage_rs::Args)]
#[usage(alias("ls"))]
#[usage(
    example("fnox provider list", header = "List providers"),
    example(
        "fnox -P production provider list",
        header = "List another profile's providers"
    ),
    after_long_help = "See also:\n- Providers: https://fnox.jdx.dev/providers/overview"
)]
pub struct ListCommand {
    /// Output provider names for shell completion (one per line)
    #[usage(long, hide)]
    pub complete: bool,
}

impl ListCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        tracing::debug!("Listing providers");
        let profiles = Config::get_profiles(cli.profile.as_slice());
        let providers = config.get_providers(&profiles)?;

        if providers.is_empty() {
            return Ok(());
        }

        // Always just output provider names, one per line
        let mut names: Vec<_> = providers.keys().collect();
        names.sort();
        for name in names {
            println!("{}", name);
        }

        Ok(())
    }
}
