use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secret;
use crate::suggest::{find_similar, format_suggestions};
use crate::temp_file_secrets::create_persistent_secret_file;
use crate::{commands::Cli, config::Config};
use clap::Args;

#[derive(Debug, Args)]
pub struct GetCommand {
    /// Secret key to retrieve
    pub key: String,

    /// Base64 decode the secret
    #[arg(long)]
    pub base64_decode: bool,
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
                // Check if this secret should be base64 decoded
                let value = if self.base64_decode {
                    let decoded_bytes =
                        data_encoding::BASE64
                            .decode(value.as_bytes())
                            .map_err(|e| FnoxError::SecretDecodeFailed {
                                details: format!("Failed to base64 decode secret: {}", e),
                            })?;
                    str::from_utf8(&decoded_bytes)
                        .map_err(|e| FnoxError::SecretDecodeFailed {
                            details: format!("decoded secret is not valid UTF-8: {}", e),
                        })?
                        .to_string()
                } else {
                    value
                };

                // Check if this secret should be written to a file
                if secret_config.as_file {
                    let file_path = create_persistent_secret_file("fnox-", &self.key, &value)?;
                    println!("{}", file_path);
                } else {
                    println!("{}", value);
                }
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
