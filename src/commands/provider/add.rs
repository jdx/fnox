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

    /// Default Proton Pass vault name (only valid with provider type proton-pass)
    #[arg(long)]
    pub vault: Option<String>,
}

impl AddCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        tracing::debug!(
            "Adding provider '{}' of type '{}'",
            self.provider,
            self.provider_type
        );

        if self.vault.is_some() && self.provider_type != ProviderType::ProtonPass {
            return Err(FnoxError::Config(
                "--vault is only supported for provider type 'proton-pass'".to_string(),
            ));
        }

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
                token: OptionStringOrSecretRef::none(),
                auth_command: None,
            },
            ProviderType::Aws => crate::config::ProviderConfig::AwsSecretsManager {
                region: StringOrSecretRef::from("us-east-1"),
                profile: OptionStringOrSecretRef::none(),
                prefix: OptionStringOrSecretRef::none(),
                auth_command: None,
            },
            ProviderType::Vault => crate::config::ProviderConfig::HashiCorpVault {
                address: StringOrSecretRef::from("http://localhost:8200"),
                path: OptionStringOrSecretRef::literal("secret"),
                token: OptionStringOrSecretRef::none(),
                namespace: OptionStringOrSecretRef::none(),
                auth_command: None,
            },
            ProviderType::Gcp => crate::config::ProviderConfig::GoogleSecretManager {
                project: StringOrSecretRef::from("my-project"),
                prefix: OptionStringOrSecretRef::none(),
                auth_command: None,
            },
            ProviderType::AwsKms => crate::config::ProviderConfig::AwsKms {
                region: StringOrSecretRef::from("us-east-1"),
                key_id: StringOrSecretRef::from("alias/my-key"),
                auth_command: None,
            },
            ProviderType::AwsParameterStore => crate::config::ProviderConfig::AwsParameterStore {
                region: StringOrSecretRef::from("us-east-1"),
                profile: OptionStringOrSecretRef::none(),
                prefix: OptionStringOrSecretRef::literal("/myapp/prod/"),
                auth_command: None,
            },
            ProviderType::AzureKms => crate::config::ProviderConfig::AzureKms {
                vault_url: StringOrSecretRef::from("https://my-vault.vault.azure.net/"),
                key_name: StringOrSecretRef::from("my-key"),
                auth_command: None,
            },
            ProviderType::AzureSecretsManager => {
                crate::config::ProviderConfig::AzureSecretsManager {
                    vault_url: StringOrSecretRef::from("https://my-vault.vault.azure.net/"),
                    prefix: OptionStringOrSecretRef::none(),
                    auth_command: None,
                }
            }
            ProviderType::GcpKms => crate::config::ProviderConfig::GcpKms {
                project: StringOrSecretRef::from("my-project"),
                location: StringOrSecretRef::from("global"),
                keyring: StringOrSecretRef::from("my-keyring"),
                key: StringOrSecretRef::from("my-key"),
                auth_command: None,
            },
            ProviderType::Bitwarden => crate::config::ProviderConfig::Bitwarden {
                collection: OptionStringOrSecretRef::none(),
                organization_id: OptionStringOrSecretRef::none(),
                profile: OptionStringOrSecretRef::none(),
                backend: None,
            },
            ProviderType::BitwardenSecretsManager => {
                crate::config::ProviderConfig::BitwardenSecretsManager {
                    project_id: OptionStringOrSecretRef::none(),
                    profile: OptionStringOrSecretRef::none(),
                }
            }
            ProviderType::Age => crate::config::ProviderConfig::AgeEncryption {
                recipients: vec!["age1...".to_string()],
                key_file: OptionStringOrSecretRef::none(),
                auth_command: None,
            },
            ProviderType::Infisical => crate::config::ProviderConfig::Infisical {
                project_id: OptionStringOrSecretRef::literal("your-project-id"),
                environment: OptionStringOrSecretRef::literal("dev"),
                path: OptionStringOrSecretRef::literal("/"),
                auth_command: None,
            },
            ProviderType::KeePass => crate::config::ProviderConfig::KeePass {
                database: StringOrSecretRef::from("~/secrets.kdbx"),
                keyfile: OptionStringOrSecretRef::none(),
                password: OptionStringOrSecretRef::none(),
            },
            ProviderType::Keychain => crate::config::ProviderConfig::Keychain {
                service: StringOrSecretRef::from("fnox"),
                prefix: OptionStringOrSecretRef::none(),
            },
            ProviderType::PasswordStore => crate::config::ProviderConfig::PasswordStore {
                prefix: OptionStringOrSecretRef::literal("fnox/"),
                store_dir: OptionStringOrSecretRef::none(),
                gpg_opts: OptionStringOrSecretRef::none(),
            },
            ProviderType::Passwordstate => crate::config::ProviderConfig::Passwordstate {
                base_url: StringOrSecretRef::from("https://passwordstate.example.com"),
                api_key: OptionStringOrSecretRef::none(),
                password_list_id: StringOrSecretRef::from("123"),
                verify_ssl: OptionStringOrSecretRef::none(),
                auth_command: None,
            },
            ProviderType::Plain => crate::config::ProviderConfig::Plain,
            ProviderType::ProtonPass => crate::config::ProviderConfig::ProtonPass {
                vault: self
                    .vault
                    .as_ref()
                    .map_or_else(OptionStringOrSecretRef::none, |vault| {
                        OptionStringOrSecretRef::literal(vault.clone())
                    }),
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
