use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use clap::Args;

#[derive(Debug, Args)]
#[command(alias = "profile")]
pub struct ProfilesCommand {
    /// Output profile names for shell completion (one per line)
    #[arg(long, hide = true)]
    pub complete: bool,
}

impl ProfilesCommand {
    pub async fn run(&self, _cli: &Cli, config: Config) -> Result<()> {
        let mut profile_names = vec!["default".to_string()];
        profile_names.extend(config.profiles.keys().cloned());
        profile_names.sort();
        profile_names.dedup();

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
                    .get_secrets(&[name.clone()])
                    .map(|s| s.len())
                    .unwrap_or(0);
                println!("  {} ({} secrets)", name, secret_count);
            }
        }
        Ok(())
    }
}
