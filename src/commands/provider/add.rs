use crate::commands::Cli;
use crate::config::{Config, ConfigValue, ProviderConfig};
use crate::error::{FnoxError, Result};
use crate::providers::{
    age::AgeConfig, aws_kms::AwsKmsConfig, aws_ps::AwsPsConfig, aws_sm::AwsSmConfig,
    azure_kms::AzureKmsConfig, azure_sm::AzureSmConfig, gcp_kms::GcpKmsConfig, gcp_sm::GcpSmConfig,
    infisical::InfisicalConfig, onepassword::OnePasswordConfig, vault::VaultConfig,
};
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
            ProviderType::OnePassword => ProviderConfig::OnePassword(OnePasswordConfig {
                vault: Some(ConfigValue::Plain("default".to_string())),
                account: None,
            }),
            ProviderType::Aws => ProviderConfig::AwsSecretsManager(AwsSmConfig {
                region: ConfigValue::Plain("us-east-1".to_string()),
                prefix: None,
            }),
            ProviderType::Vault => ProviderConfig::HashiCorpVault(VaultConfig {
                address: ConfigValue::Plain("http://localhost:8200".to_string()),
                path: Some(ConfigValue::Plain("secret".to_string())),
                token: None,
            }),
            ProviderType::Gcp => ProviderConfig::GoogleSecretManager(GcpSmConfig {
                project: ConfigValue::Plain("my-project".to_string()),
                prefix: None,
            }),
            ProviderType::AwsKms => ProviderConfig::AwsKms(AwsKmsConfig {
                region: ConfigValue::Plain("us-east-1".to_string()),
                key_id: ConfigValue::Plain("alias/my-key".to_string()),
            }),
            ProviderType::AwsParameterStore => ProviderConfig::AwsParameterStore(AwsPsConfig {
                region: ConfigValue::Plain("us-east-1".to_string()),
                prefix: Some(ConfigValue::Plain("/myapp/prod/".to_string())),
            }),
            ProviderType::AzureKms => ProviderConfig::AzureKms(AzureKmsConfig {
                vault_url: ConfigValue::Plain("https://my-vault.vault.azure.net/".to_string()),
                key_name: ConfigValue::Plain("my-key".to_string()),
            }),
            ProviderType::AzureSecretsManager => {
                ProviderConfig::AzureSecretsManager(AzureSmConfig {
                    vault_url: ConfigValue::Plain("https://my-vault.vault.azure.net/".to_string()),
                    prefix: None,
                })
            }
            ProviderType::GcpKms => ProviderConfig::GcpKms(GcpKmsConfig {
                project: ConfigValue::Plain("my-project".to_string()),
                location: ConfigValue::Plain("global".to_string()),
                keyring: ConfigValue::Plain("my-keyring".to_string()),
                key: ConfigValue::Plain("my-key".to_string()),
            }),
            ProviderType::Age => ProviderConfig::AgeEncryption(AgeConfig {
                recipients: vec![ConfigValue::Plain("age1...".to_string())],
                key_file: None,
            }),
            ProviderType::Infisical => ProviderConfig::Infisical(InfisicalConfig {
                project_id: Some(ConfigValue::Plain("your-project-id".to_string())),
                environment: Some(ConfigValue::Plain("dev".to_string())),
                path: Some(ConfigValue::Plain("/".to_string())),
            }),
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
