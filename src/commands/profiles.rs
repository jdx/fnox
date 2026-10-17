use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;

/// List profiles and how many secrets each provides
///
/// Prints each profile in the loaded config, from `[profiles.<name>]` tables and
/// profile files such as `fnox.staging.toml`, with its number of secrets,
/// including inherited top-level secrets. `default` is always listed.
#[derive(Debug, usage_rs::Args)]
#[usage(alias_hidden = "profile")]
#[usage(
    example("fnox profiles", header = "List profiles"),
    example(
        "fnox -P aws,staging list",
        header = "Layer two profiles for one command"
    ),
    after_long_help = "See also:\n- Profiles: https://fnox.jdx.dev/guide/profiles"
)]
pub struct ProfilesCommand {
    /// Output profile names for shell completion (one per line)
    #[usage(long, hide)]
    pub complete: bool,
}

impl ProfilesCommand {
    pub async fn run(&self, _cli: &Cli, config: Config) -> Result<()> {
        let profile_names = config.available_profiles();

        if self.complete {
            // Output for completion
            for name in profile_names {
                println!("{}", name);
            }
        } else {
            // Normal output
            println!("Available profiles:");
            for name in profile_names {
                let secret_count = config
                    .get_secrets(std::slice::from_ref(&name))
                    .map(|s| s.len())
                    .unwrap_or(0);
                println!("  {} ({} secrets)", name, secret_count);
            }
        }
        Ok(())
    }
}
