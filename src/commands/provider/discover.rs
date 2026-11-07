use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use fnox_core::auth_prompt::prompt_and_run_auth;
use fnox_core::providers::discovery::DiscoveredItem;

/// Discover provider items, optionally narrowed by tags
///
/// Currently supports 1Password. Outputs item IDs, titles, tags, and vaults,
/// never secret fields. Uses the configured account and vault, or all accessible
/// vaults when none is configured. Provider credential references are resolved
/// directly, bypassing the daemon cache. Does not modify fnox.toml.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example(
        "fnox provider discover op --tags project/example",
        header = "Find tagged items"
    ),
    example(
        "fnox provider discover op --tags project/example --json",
        header = "Read item metadata as JSON"
    ),
    after_long_help = "See also:\n- 1Password: https://fnox.jdx.dev/providers/1password"
)]
pub struct DiscoverCommand {
    /// Configured provider name
    pub provider: String,
    /// Output a JSON array of item metadata
    #[usage(long)]
    pub json: bool,
    /// Tag filters (comma-separated or repeated); omitted lists all items in scope
    #[usage(long, delimiter = ',')]
    pub tags: Vec<String>,
}

impl DiscoverCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profiles = Config::get_profiles(cli.profile.as_slice());
        let providers = config.get_providers(&profiles)?;
        let provider_config = providers
            .get(&self.provider)
            .ok_or_else(|| FnoxError::Config(format!("Provider '{}' not found", self.provider)))?;
        if provider_config.provider_type() != "1password" {
            return Err(FnoxError::Provider(format!(
                "Item discovery is not supported for provider '{}'",
                self.provider
            )));
        }
        let provider = crate::providers::get_provider_resolved(
            &config,
            &profiles,
            &self.provider,
            provider_config,
        )
        .await?;
        let items = match provider.discover(&self.tags).await {
            Ok(items) => items,
            Err(error) => {
                if prompt_and_run_auth(
                    &config,
                    provider_config,
                    &self.provider,
                    provider.auth_command().as_deref(),
                    &error,
                )? {
                    provider.discover(&self.tags).await?
                } else {
                    return Err(error);
                }
            }
        };
        if self.json {
            println!("{}", serde_json::to_string_pretty(&items)?);
        } else {
            print!("{}", format_items(&items));
        }
        Ok(())
    }
}

/// Tab-separated metadata, with control characters escaped for terminal safety.
pub fn format_items(items: &[DiscoveredItem]) -> String {
    fn display(value: &str) -> String {
        let mut escaped = String::new();
        for character in value.chars() {
            if character.is_control() {
                escaped.extend(character.escape_default());
            } else {
                escaped.push(character);
            }
        }
        escaped
    }
    let mut output = String::from("ID\tVAULT\tVAULT_ID\tTITLE\tTAGS\n");
    for item in items {
        let vault = item.vault.as_ref().map_or("", |vault| vault.name.as_str());
        let vault_id = item.vault.as_ref().map_or("", |vault| vault.id.as_str());
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            display(&item.id),
            display(vault),
            display(vault_id),
            display(&item.title),
            display(&item.tags.join(","))
        ));
    }
    output
}

#[cfg(test)]
#[path = "../../../test/commands/provider/discover.rs"]
mod tests;
