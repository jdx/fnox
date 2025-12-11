use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::providers::{OptionStringOrSecretRef, StringOrSecretRef};
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
                vault: OptionStringOrSecretRef::literal("default"),
                account: OptionStringOrSecretRef::none(),
            },
            ProviderType::Aws => crate::config::ProviderConfig::AwsSecretsManager {
                region: StringOrSecretRef::from("us-east-1"),
                prefix: OptionStringOrSecretRef::none(),
            },
            ProviderType::Vault => crate::config::ProviderConfig::HashiCorpVault {
                address: StringOrSecretRef::from("http://localhost:8200"),
                path: OptionStringOrSecretRef::literal("secret"),
                token: OptionStringOrSecretRef::none(),
            },
            ProviderType::Gcp => crate::config::ProviderConfig::GoogleSecretManager {
                project: StringOrSecretRef::from("my-project"),
                prefix: OptionStringOrSecretRef::none(),
            },
            ProviderType::AwsKms => crate::config::ProviderConfig::AwsKms {
                region: StringOrSecretRef::from("us-east-1"),
                key_id: StringOrSecretRef::from("alias/my-key"),
            },
            ProviderType::AwsParameterStore => crate::config::ProviderConfig::AwsParameterStore {
                region: StringOrSecretRef::from("us-east-1"),
                prefix: OptionStringOrSecretRef::literal("/myapp/prod/"),
            },
            ProviderType::AzureKms => crate::config::ProviderConfig::AzureKms {
                vault_url: StringOrSecretRef::from("https://my-vault.vault.azure.net/"),
                key_name: StringOrSecretRef::from("my-key"),
            },
            ProviderType::AzureSecretsManager => {
                crate::config::ProviderConfig::AzureSecretsManager {
                    vault_url: StringOrSecretRef::from("https://my-vault.vault.azure.net/"),
                    prefix: OptionStringOrSecretRef::none(),
                }
            }
            ProviderType::GcpKms => crate::config::ProviderConfig::GcpKms {
                project: StringOrSecretRef::from("my-project"),
                location: StringOrSecretRef::from("global"),
                keyring: StringOrSecretRef::from("my-keyring"),
                key: StringOrSecretRef::from("my-key"),
            },
            ProviderType::Age => crate::config::ProviderConfig::AgeEncryption {
                recipients: vec!["age1...".to_string()],
                key_file: OptionStringOrSecretRef::none(),
            },
            ProviderType::Infisical => crate::config::ProviderConfig::Infisical {
                project_id: OptionStringOrSecretRef::literal("your-project-id"),
                environment: OptionStringOrSecretRef::literal("dev"),
                path: OptionStringOrSecretRef::literal("/"),
            },
            ProviderType::Passwordstate => crate::config::ProviderConfig::Passwordstate {
                base_url: StringOrSecretRef::from("https://passwordstate.example.com"),
                api_key: OptionStringOrSecretRef::none(),
                password_list_id: StringOrSecretRef::from("123"),
                verify_ssl: OptionStringOrSecretRef::none(),
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
