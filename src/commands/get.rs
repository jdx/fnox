use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secret;
use crate::suggest::{find_similar, format_suggestions};
use crate::{commands::Cli, config::Config};
use clap::Args;

#[derive(Debug, Args)]
pub struct GetCommand {
    /// Secret key to retrieve
    pub key: String,
}

impl GetCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Getting secret '{}' from profile '{}'", self.key, profile);

        // Validate the configuration first
        config.validate()?;

        // Get the profile secrets
        let profile_secrets = config.get_secrets(&profile)?;

        // Get the secret config
        let secret_config = profile_secrets.get(&self.key).ok_or_else(|| {
            // Find similar secret names for suggestion
            let available_keys: Vec<_> = profile_secrets.keys().map(|s| s.as_str()).collect();
            let similar = find_similar(&self.key, available_keys);
            let suggestion = format_suggestions(&similar);

            FnoxError::SecretNotFound {
                key: self.key.clone(),
                profile: profile.clone(),
                config_path: config.secret_sources.get(&self.key).cloned(),
                suggestion,
            }
        })?;

        // Resolve the secret using centralized resolver
        match resolve_secret(&config, &profile, &self.key, secret_config).await {
            Ok(Some(value)) => {
                println!("{}", value);
                Ok(())
            }
            Ok(None) => {
                // Secret not found but if_missing allows it
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
