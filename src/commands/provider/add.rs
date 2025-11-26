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
}

impl AddCommand {
    pub async fn run(&self, cli: &Cli, mut config: Config) -> Result<()> {
        tracing::debug!(
            "Adding provider '{}' of type '{}'",
            self.provider,
            self.provider_type
        );

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
        config.save(&cli.config)?;

        println!("✓ Added provider '{}'", self.provider);
        println!(
            "\nNote: Please edit '{}' to configure the provider settings.",
            cli.config.display()
        );

        Ok(())
    }
}
