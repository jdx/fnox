use crate::commands::Cli;
use crate::config::{Config, IfMissing, ProviderConfig};
use crate::error::{FnoxError, Result};
use clap::Args;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Debug, Args)]
#[command(visible_aliases = ["s"])]
pub struct SetCommand {
    /// Secret key (environment variable name)
    pub key: String,

    /// Secret value (reads from stdin if not provided)
    pub value: Option<String>,

    /// Description of the secret
    #[arg(short = 'd', long)]
    pub description: Option<String>,

    /// Key name in the provider (if different from env var name)
    #[arg(short = 'k', long)]
    pub key_name: Option<String>,

    /// Provider to fetch from
    #[arg(short = 'p', long)]
    pub provider: Option<String>,

    /// Default value to use if secret is not found
    #[arg(long)]
    pub default: Option<String>,

    /// What to do if the secret is missing (error, warn, ignore)
    #[arg(long)]
    pub if_missing: Option<IfMissing>,
}

impl SetCommand {
    pub async fn run(&self, cli: &Cli, mut config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Setting secret '{}' in profile '{}'", self.key, profile);

        // Check if we're only setting metadata (no actual secret value)
        // Note: provider is not considered "metadata only" because we need it for encryption
        // key_name is metadata-only because it just sets the reference without encrypting
        let has_metadata = self.description.is_some()
            || self.if_missing.is_some()
            || self.default.is_some()
            || self.key_name.is_some();

        // Get the secret value if provided
        let secret_value = if let Some(ref v) = self.value {
            // Value provided as argument
            Some(v.clone())
        } else if has_metadata {
            // Only metadata is being set, no secret value needed
            None
        } else if !atty::is(atty::Stream::Stdin) {
            // Read from stdin if piped
            tracing::debug!("Reading secret value from stdin");
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| FnoxError::Config(format!("Failed to read from stdin: {}", e)))?;
            Some(buffer.trim().to_string())
        } else {
            // Interactive terminal - prompt for value
            let value = demand::Input::new("Enter secret value")
                .prompt("Secret value: ")
                .password(true)
                .run()
                .map_err(|e| FnoxError::Config(format!("Failed to read input: {}", e)))?;
            Some(value)
        };

        // Determine which provider to use
        let provider_name_to_use = if let Some(ref provider_name) = self.provider {
            Some(provider_name.clone())
        } else {
            // Try to use default provider if available, but it's OK if there isn't one
            // (will store as plaintext)
            config.get_default_provider(&profile)?
        };

        // Handle provider-specific behavior (before we get mutable borrow)
        let (encrypted_value, remote_key_name) = if let Some(ref value) = secret_value {
            if let Some(ref provider_name) = provider_name_to_use {
                // Get the provider config
                let providers = config.get_providers(&profile);
                if let Some(provider_config) = providers.get(provider_name) {
                    // Get the provider and check its capabilities
                    let provider = crate::providers::get_provider(provider_config)?;
                    let capabilities = provider.capabilities();

                    // Ensure the provider has at least one capability
                    if capabilities.is_empty() {
                        return Err(FnoxError::Config(format!(
                            "Provider '{}' has no capabilities defined",
                            provider_name
                        )));
                    }

                    let is_encryption_provider =
                        capabilities.contains(&crate::providers::ProviderCapability::Encryption);
                    let is_remote_storage_provider =
                        capabilities.contains(&crate::providers::ProviderCapability::RemoteStorage);

                    if is_encryption_provider {
                        tracing::debug!(
                            "Encrypting secret value with provider '{}'",
                            provider_name
                        );

                        // Encrypt with the provider
                        match provider
                            .encrypt(
                                value,
                                cli.age_key_file.as_ref().map(PathBuf::from).as_deref(),
                            )
                            .await
                        {
                            Ok(encrypted) => (Some(encrypted), None),
                            Err(e) => {
                                // Provider doesn't support encryption, store plaintext
                                tracing::warn!(
                                    "Encryption not supported for provider '{}': {}. Storing plaintext.",
                                    provider_name,
                                    e
                                );
                                (Some(value.clone()), None)
                            }
                        }
                    } else if is_remote_storage_provider {
                        tracing::debug!(
                            "Storing secret '{}' in remote provider '{}'",
                            self.key,
                            provider_name
                        );

                        // Push the secret to the remote provider
                        match provider_config {
                            ProviderConfig::AwsSecretsManager { region, prefix } => {
                                let sm_provider =
                                    crate::providers::aws_sm::AwsSecretsManagerProvider::new(
                                        region.clone(),
                                        prefix.clone(),
                                    );
                                let secret_name = sm_provider.get_secret_name(&self.key);
                                sm_provider.put_secret(&secret_name, value).await?;

                                // Store just the key name (without prefix) in config
                                (None, Some(self.key.clone()))
                            }
                            ProviderConfig::Keychain { service, prefix } => {
                                let keychain_provider =
                                    crate::providers::keychain::KeychainProvider::new(
                                        service.clone(),
                                        prefix.clone(),
                                    );
                                keychain_provider.put_secret(&self.key, value).await?;

                                // Store just the key name (without prefix) in config
                                (None, Some(self.key.clone()))
                            }
                            ProviderConfig::PasswordStore {
                                prefix,
                                store_dir,
                                gpg_opts,
                            } => {
                                let pass_provider =
                                    crate::providers::password_store::PasswordStoreProvider::new(
                                        prefix.clone(),
                                        store_dir.clone(),
                                        gpg_opts.clone(),
                                    );

                                let key_name = self.key_name.as_deref().unwrap_or(&self.key);
                                pass_provider.put_secret(key_name, value).await?;

                                // Store just the key name (without prefix) in config
                                (None, Some(key_name.to_string()))
                            }
                            ProviderConfig::AzureSecretsManager { vault_url, prefix } => {
                                let azure_sm_provider =
                                    crate::providers::azure_sm::AzureSecretsManagerProvider::new(
                                        vault_url.clone(),
                                        prefix.clone(),
                                    );
                                let secret_name = azure_sm_provider.get_secret_name(&self.key);
                                azure_sm_provider.put_secret(&secret_name, value).await?;

                                // Store just the key name (without prefix) in config
                                (None, Some(self.key.clone()))
                            }
                            _ => {
                                // Other remote storage providers not yet implemented
                                tracing::warn!(
                                    "Remote storage not yet implemented for provider '{}', storing plaintext",
                                    provider_name
                                );
                                (Some(value.clone()), None)
                            }
                        }
                    } else {
                        // Not an encryption or remote storage provider
                        (None, None)
                    }
                } else {
                    return Err(FnoxError::Config(format!(
                        "Provider '{}' not found in configuration",
                        provider_name
                    )));
                }
            } else {
                // No provider specified or available
                (None, None)
            }
        } else {
            (None, None)
        };

        // Now update the config
        let profile_secrets = config.get_secrets_mut(&profile);

        // Get or create the secret config
        let secret_config = profile_secrets.entry(self.key.clone()).or_default();

        // Update metadata
        if let Some(ref desc) = self.description {
            secret_config.description = Some(desc.clone());
        }

        if let Some(if_missing) = self.if_missing {
            secret_config.if_missing = Some(if_missing);
        }

        if let Some(ref default) = self.default {
            secret_config.default = Some(default.clone());
        }

        // Set the provider if explicitly specified
        if let Some(ref provider) = self.provider {
            secret_config.provider = Some(provider.clone());
        } else if provider_name_to_use.is_some() && secret_config.provider.is_none() {
            // If we have a default provider and the secret doesn't already have one,
            // store it explicitly for clarity
            secret_config.provider = provider_name_to_use.clone();
        }

        if let Some(ref key_name) = self.key_name {
            secret_config.value = Some(key_name.clone());
        } else if let Some(ref value) = secret_value {
            // Priority order: remote key name, encrypted value, then plaintext
            if let Some(remote_key) = remote_key_name {
                // Store the key name for remote storage providers
                secret_config.value = Some(remote_key);
            } else if let Some(encrypted) = encrypted_value {
                // Store encrypted value for encryption providers
                secret_config.value = Some(encrypted);
            } else if provider_name_to_use.is_some() {
                // Provider specified or default provider available (but not an encryption/remote provider)
                secret_config.value = Some(value.clone());
            } else {
                // No provider specified or available, store as default value
                secret_config.value = Some(value.clone());
                secret_config.default = Some(value.clone());
            }
        }

        let secret_config = profile_secrets.get(&self.key).unwrap().clone();
        let _ = profile_secrets; // Release the mutable borrow

        // Save the secret to its source file (or to the current directory's config)
        let current_dir = std::env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {}", e)))?;
        let default_target = current_dir.join(&cli.config);
        config.save_secret_to_source(&self.key, &secret_config, &profile, &default_target)?;

        let check = console::style("✓").green();
        let styled_key = console::style(&self.key).cyan();
        let styled_profile = console::style(&profile).magenta();
        if profile == "default" {
            println!("{check} Set secret {styled_key}");
        } else {
            println!("{check} Set secret {styled_key} in profile {styled_profile}");
        }

        Ok(())
    }
}
