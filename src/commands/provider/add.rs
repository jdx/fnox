use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use clap::Args;

use super::ProviderType;

#[derive(Debug, Args)]
#[command(visible_aliases = ["a", "set"])]
pub struct AddCommand {
    /// Provider name
    pub provider: String,

    /// Provider type
    #[arg(value_enum)]
    pub provider_type: ProviderType,

    /// Add to the global config file (~/.config/fnox/config.toml)
    #[arg(short = 'g', long)]
    pub global: bool,
}

impl AddCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        tracing::debug!(
            "Adding provider '{}' of type '{}'",
            self.provider,
            self.provider_type
        );

        // Determine the target config file
        let target_path = if self.global {
            let global_path = Config::global_config_path();
            // Create parent directory if it doesn't exist
            if let Some(parent) = global_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    FnoxError::Config(format!(
                        "Failed to create config directory '{}': {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
            global_path
        } else {
            let current_dir = std::env::current_dir().map_err(|e| {
                FnoxError::Config(format!("Failed to get current directory: {}", e))
            })?;
            current_dir.join(&cli.config)
        };

        // Load the target config file (or create new if it doesn't exist)
        let mut config = if target_path.exists() {
            Config::load(&target_path)?
        } else {
            Config::new()
        };

        if config.providers.contains_key(&self.provider) {
            return Err(FnoxError::Config(format!(
                "Provider '{}' already exists",
                self.provider
            )));
        }

        // Create a template provider config based on type
        let provider_config = match self.provider_type {
            ProviderType::OnePassword => crate::config::ProviderConfig::OnePassword {
                vault: Some("default".to_string()),
                account: None,
            },
            ProviderType::Aws => crate::config::ProviderConfig::AwsSecretsManager {
                region: "us-east-1".to_string(),
                prefix: None,
            },
            ProviderType::Vault => crate::config::ProviderConfig::HashiCorpVault {
                address: "http://localhost:8200".to_string(),
                path: Some("secret".to_string()),
                token: None,
            },
            ProviderType::Gcp => crate::config::ProviderConfig::GoogleSecretManager {
                project: "my-project".to_string(),
                prefix: None,
            },
            ProviderType::AwsKms => crate::config::ProviderConfig::AwsKms {
                region: "us-east-1".to_string(),
                key_id: "alias/my-key".to_string(),
            },
            ProviderType::AwsParameterStore => crate::config::ProviderConfig::AwsParameterStore {
                region: "us-east-1".to_string(),
                prefix: Some("/myapp/prod/".to_string()),
            },
            ProviderType::AzureKms => crate::config::ProviderConfig::AzureKms {
                vault_url: "https://my-vault.vault.azure.net/".to_string(),
                key_name: "my-key".to_string(),
            },
            ProviderType::AzureSecretsManager => {
                crate::config::ProviderConfig::AzureSecretsManager {
                    vault_url: "https://my-vault.vault.azure.net/".to_string(),
                    prefix: None,
                }
            }
            ProviderType::GcpKms => crate::config::ProviderConfig::GcpKms {
                project: "my-project".to_string(),
                location: "global".to_string(),
                keyring: "my-keyring".to_string(),
                key: "my-key".to_string(),
            },
            ProviderType::Age => crate::config::ProviderConfig::AgeEncryption {
                recipients: vec!["age1...".to_string()],
                key_file: None,
            },
            ProviderType::Infisical => crate::config::ProviderConfig::Infisical {
                project_id: Some("your-project-id".to_string()),
                environment: Some("dev".to_string()),
                path: Some("/".to_string()),
            },
        };

        config
            .providers
            .insert(self.provider.clone(), provider_config);
        config.save(&target_path)?;

        let global_suffix = if self.global { " (global)" } else { "" };
        println!("✓ Added provider '{}'{}", self.provider, global_suffix);
        println!(
            "\nNote: Please edit '{}' to configure the provider settings.",
            target_path.display()
        );

        Ok(())
    }
}
