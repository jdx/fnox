use crate::commands::Cli;
use crate::config::{Config, ProviderConfig, SecretConfig};
use crate::error::{FnoxError, Result};
use clap::Args;
use demand::{Confirm, DemandOption, Input, Select};

#[derive(Debug, Args)]
#[command(visible_alias = "i")]
pub struct InitCommand {
    /// Initialize the global config file (~/.config/fnox/config.toml)
    #[arg(short = 'g', long)]
    global: bool,

    /// Overwrite existing configuration file
    #[arg(long)]
    force: bool,

    /// Skip the interactive wizard and create a minimal config
    #[arg(long)]
    skip_wizard: bool,
}

impl InitCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        // Determine the target config path
        let config_path = if self.global {
            Config::global_config_path()
        } else {
            cli.config.clone()
        };

        tracing::debug!(
            "Initializing new fnox configuration at '{}'",
            config_path.display()
        );

        if config_path.exists() && !self.force {
            return Err(FnoxError::Config(format!(
                "Configuration file '{}' already exists. Use --force to overwrite.",
                config_path.display()
            )));
        }

        // Create parent directory if it doesn't exist (for global config)
        if self.global
            && let Some(parent) = config_path.parent()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                FnoxError::Config(format!(
                    "Failed to create config directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let config = if self.skip_wizard || !atty::is(atty::Stream::Stdin) {
            // Non-interactive mode
            Config::new()
        } else {
            // Interactive wizard mode
            self.run_wizard().await?
        };

        config.save(&config_path)?;

        println!(
            "\n✓ Created new fnox configuration at '{}'",
            config_path.display()
        );
        if self.global {
            println!("\nThis global config will be used as the base for all projects.");
        }
        println!("\nNext steps:");
        println!(
            "  • Add secrets: fnox set MY_SECRET <value>{}",
            if self.global { " --global" } else { "" }
        );
        println!("  • List secrets: fnox list");
        println!("  • Use in commands: fnox exec -- <command>");

        Ok(())
    }

    async fn run_wizard(&self) -> Result<Config> {
        println!("\n🔐 Welcome to fnox setup wizard!\n");
        println!("This will help you configure your first secret provider.\n");

        // Ask if they want to set up a provider
        let setup_provider = Confirm::new("Would you like to set up a provider now?")
            .affirmative("Yes")
            .negative("No, I'll configure it later")
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        if !setup_provider {
            println!("\n✓ Creating minimal configuration file.");
            return Ok(Config::new());
        }

        // Select provider category
        let category = Select::new("What type of provider do you want to use?")
            .description("Choose a category based on your security and convenience needs")
            .filterable(false)
            .option(
                DemandOption::new("Local (easy to start)")
                    .label("Local (easy to start)")
                    .description("Plain text or local encryption - no external dependencies"),
            )
            .option(
                DemandOption::new("Password Manager")
                    .description("1Password, Bitwarden - use your existing password manager"),
            )
            .option(
                DemandOption::new("Cloud KMS")
                    .description("AWS KMS, Azure Key Vault, GCP KMS - encrypt with cloud keys"),
            )
            .option(
                DemandOption::new("Cloud Secrets Manager")
                    .description("AWS, Azure, GCP, HashiCorp Vault - store secrets remotely"),
            )
            .option(
                DemandOption::new("OS Keychain")
                    .description("Use your operating system's secure keychain"),
            )
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        let (provider_name, provider_config) = match category {
            "Local (easy to start)" => self.setup_local_provider().await?,
            "Password Manager" => self.setup_password_manager().await?,
            "Cloud KMS" => self.setup_cloud_kms().await?,
            "Cloud Secrets Manager" => self.setup_cloud_secrets_manager().await?,
            "OS Keychain" => self.setup_keychain().await?,
            _ => return Err(FnoxError::Config("Unknown provider category".to_string())),
        };

        // Create config with provider
        let mut config = Config::new();
        config
            .providers
            .insert(provider_name.clone(), provider_config);
        config.default_provider = Some(provider_name);

        // Ask if they want to add an example secret
        let add_example = Confirm::new("Would you like to add an example secret?")
            .affirmative("Yes")
            .negative("No")
            .run()
            .unwrap_or(false);

        if add_example {
            let secret_name = Input::new("Secret name:")
                .placeholder("MY_SECRET")
                .run()
                .unwrap_or_else(|_| "EXAMPLE_SECRET".to_string());

            let description = Input::new("Description (optional):")
                .placeholder("Example secret for testing")
                .run()
                .ok();

            config.secrets.insert(
                secret_name,
                SecretConfig {
                    description: description.filter(|s| !s.is_empty()),
                    provider: config.default_provider.clone(),
                    value: None, // Will be set with `fnox set` later
                    default: None,
                    if_missing: None,
                    source_path: None,
                },
            );
        }

        Ok(config)
    }

    async fn setup_local_provider(&self) -> Result<(String, ProviderConfig)> {
        let provider_type = Select::new("Select local provider:")
            .filterable(false)
            .option(
                DemandOption::new("plain")
                    .label("Plain text")
                    .description("No encryption - stores values directly in config (not recommended for sensitive data)")
            )
            .option(
                DemandOption::new("age")
                    .label("Age encryption")
                    .description("Modern encryption tool - encrypts values with age keys")
            )
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        match provider_type {
            "plain" => {
                println!("\n⚠️  Plain provider stores secrets unencrypted in your config file.");
                println!("   Only use this for non-sensitive values or development.\n");

                let name = Input::new("Provider name:")
                    .placeholder("plain")
                    .run()
                    .unwrap_or_else(|_| "plain".to_string());

                Ok((name, ProviderConfig::Plain))
            }
            "age" => {
                println!("\n📝 Age encryption setup:");
                println!("   Age uses public/private key pairs for encryption.");
                println!("   Generate a key with: age-keygen -o ~/.config/fnox/age.txt\n");

                let recipient = Input::new("Age public key (recipient):")
                    .placeholder("age1...")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                if recipient.is_empty() {
                    return Err(FnoxError::Config(
                        "Age recipient cannot be empty".to_string(),
                    ));
                }

                let name = Input::new("Provider name:")
                    .placeholder("age")
                    .run()
                    .unwrap_or_else(|_| "age".to_string());

                Ok((
                    name,
                    ProviderConfig::AgeEncryption {
                        recipients: vec![recipient],
                        key_file: None,
                    },
                ))
            }
            _ => Err(FnoxError::Config("Unknown local provider".to_string())),
        }
    }

    async fn setup_password_manager(&self) -> Result<(String, ProviderConfig)> {
        let provider_type = Select::new("Select password manager:")
            .filterable(false)
            .option(
                DemandOption::new("1password")
                    .label("1Password")
                    .description("Requires 1Password CLI and service account token"),
            )
            .option(
                DemandOption::new("bitwarden")
                    .label("Bitwarden")
                    .description("Requires Bitwarden CLI and session token"),
            )
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        match provider_type {
            "1password" => {
                println!("\n🔑 1Password setup:");
                println!("   Requires: 1Password CLI (op) and a service account token");
                println!("   Set token: export OP_SERVICE_ACCOUNT_TOKEN=<token>\n");

                let vault = Input::new("Vault name (optional):")
                    .placeholder("")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let account = Input::new("Account (optional, e.g., my.1password.com):")
                    .placeholder("")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let name = Input::new("Provider name:")
                    .placeholder("onepass")
                    .run()
                    .unwrap_or_else(|_| "onepass".to_string());

                Ok((name, ProviderConfig::OnePassword { vault, account }))
            }
            "bitwarden" => {
                println!("\n🔑 Bitwarden setup:");
                println!("   Requires: Bitwarden CLI (bw) and session token");
                println!("   Login: bw login && export BW_SESSION=$(bw unlock --raw)\n");

                let collection = Input::new("Collection ID (optional):")
                    .placeholder("")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let organization_id = Input::new("Organization ID (optional):")
                    .placeholder("")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let profile = Input::new("Bitwarden CLI profile (optional):")
                    .placeholder("")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let name = Input::new("Provider name:")
                    .placeholder("bitwarden")
                    .run()
                    .unwrap_or_else(|_| "bitwarden".to_string());

                Ok((
                    name,
                    ProviderConfig::Bitwarden {
                        collection,
                        organization_id,
                        profile,
                        backend: None,
                    },
                ))
            }
            _ => Err(FnoxError::Config("Unknown password manager".to_string())),
        }
    }

    async fn setup_cloud_kms(&self) -> Result<(String, ProviderConfig)> {
        let provider_type = Select::new("Select cloud KMS provider:")
            .filterable(false)
            .option(
                DemandOption::new("aws-kms")
                    .label("AWS KMS")
                    .description("AWS Key Management Service"),
            )
            .option(
                DemandOption::new("azure-kms")
                    .label("Azure Key Vault")
                    .description("Azure Key Vault for encryption"),
            )
            .option(
                DemandOption::new("gcp-kms")
                    .label("GCP KMS")
                    .description("Google Cloud Key Management Service"),
            )
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        match provider_type {
            "aws-kms" => {
                println!("\n☁️  AWS KMS setup:");
                println!("   Encrypts secrets using AWS KMS keys");
                println!("   Requires AWS credentials configured\n");

                let key_id = Input::new("KMS Key ID (ARN or alias):")
                    .placeholder("arn:aws:kms:us-east-1:123456789012:key/...")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let region = Input::new("AWS Region:")
                    .placeholder("us-east-1")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let name = Input::new("Provider name:")
                    .placeholder("kms")
                    .run()
                    .unwrap_or_else(|_| "kms".to_string());

                Ok((name, ProviderConfig::AwsKms { key_id, region }))
            }
            "azure-kms" => {
                println!("\n☁️  Azure Key Vault setup:");
                println!("   Encrypts secrets using Azure Key Vault keys");
                println!("   Requires Azure credentials configured\n");

                let vault_url = Input::new("Key Vault URL:")
                    .placeholder("https://my-vault.vault.azure.net/")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let key_name = Input::new("Key name:")
                    .placeholder("my-key")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let name = Input::new("Provider name:")
                    .placeholder("azure-kms")
                    .run()
                    .unwrap_or_else(|_| "azure-kms".to_string());

                Ok((
                    name,
                    ProviderConfig::AzureKms {
                        vault_url,
                        key_name,
                    },
                ))
            }
            "gcp-kms" => {
                println!("\n☁️  GCP KMS setup:");
                println!("   Encrypts secrets using Google Cloud KMS");
                println!("   Requires GCP credentials configured\n");

                let project = Input::new("GCP Project ID:")
                    .placeholder("my-project")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let location = Input::new("Location:")
                    .placeholder("us-east1")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let keyring = Input::new("Keyring name:")
                    .placeholder("my-keyring")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let key = Input::new("Key name:")
                    .placeholder("my-key")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let name = Input::new("Provider name:")
                    .placeholder("gcp-kms")
                    .run()
                    .unwrap_or_else(|_| "gcp-kms".to_string());

                Ok((
                    name,
                    ProviderConfig::GcpKms {
                        project,
                        location,
                        keyring,
                        key,
                    },
                ))
            }
            _ => Err(FnoxError::Config("Unknown cloud KMS provider".to_string())),
        }
    }

    async fn setup_cloud_secrets_manager(&self) -> Result<(String, ProviderConfig)> {
        let provider_type = Select::new("Select secrets manager:")
            .filterable(false)
            .option(
                DemandOption::new("aws-sm")
                    .label("AWS Secrets Manager")
                    .description("AWS Secrets Manager"),
            )
            .option(
                DemandOption::new("azure-sm")
                    .label("Azure Key Vault Secrets")
                    .description("Azure Key Vault secret storage"),
            )
            .option(
                DemandOption::new("gcp-sm")
                    .label("GCP Secret Manager")
                    .description("Google Cloud Secret Manager"),
            )
            .option(
                DemandOption::new("vault")
                    .label("HashiCorp Vault")
                    .description("HashiCorp Vault"),
            )
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        match provider_type {
            "aws-sm" => {
                println!("\n☁️  AWS Secrets Manager setup:");
                println!("   Stores secrets in AWS Secrets Manager");
                println!("   Requires AWS credentials configured\n");

                let region = Input::new("AWS Region:")
                    .placeholder("us-east-1")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let prefix = Input::new("Secret name prefix (optional):")
                    .placeholder("fnox/")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let name = Input::new("Provider name:")
                    .placeholder("sm")
                    .run()
                    .unwrap_or_else(|_| "sm".to_string());

                Ok((name, ProviderConfig::AwsSecretsManager { region, prefix }))
            }
            "azure-sm" => {
                println!("\n☁️  Azure Key Vault Secrets setup:");
                println!("   Stores secrets in Azure Key Vault");
                println!("   Requires Azure credentials configured\n");

                let vault_url = Input::new("Key Vault URL:")
                    .placeholder("https://my-vault.vault.azure.net/")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let prefix = Input::new("Secret name prefix (optional):")
                    .placeholder("fnox-")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let name = Input::new("Provider name:")
                    .placeholder("azure-sm")
                    .run()
                    .unwrap_or_else(|_| "azure-sm".to_string());

                Ok((
                    name,
                    ProviderConfig::AzureSecretsManager { vault_url, prefix },
                ))
            }
            "gcp-sm" => {
                println!("\n☁️  GCP Secret Manager setup:");
                println!("   Stores secrets in Google Cloud Secret Manager");
                println!("   Requires GCP credentials configured\n");

                let project = Input::new("GCP Project ID:")
                    .placeholder("my-project")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let prefix = Input::new("Secret name prefix (optional):")
                    .placeholder("fnox-")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let name = Input::new("Provider name:")
                    .placeholder("gcp-sm")
                    .run()
                    .unwrap_or_else(|_| "gcp-sm".to_string());

                Ok((
                    name,
                    ProviderConfig::GoogleSecretManager { project, prefix },
                ))
            }
            "vault" => {
                println!("\n🔐 HashiCorp Vault setup:");
                println!("   Stores secrets in HashiCorp Vault");
                println!("   Requires Vault address and token\n");

                let address = Input::new("Vault address:")
                    .placeholder("https://vault.example.com:8200")
                    .run()
                    .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

                let path = Input::new("Vault path prefix (optional):")
                    .placeholder("secret/data/fnox")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let token = Input::new("Vault token (optional, can use VAULT_TOKEN env var):")
                    .placeholder("")
                    .run()
                    .ok()
                    .filter(|s| !s.is_empty());

                let name = Input::new("Provider name:")
                    .placeholder("vault")
                    .run()
                    .unwrap_or_else(|_| "vault".to_string());

                Ok((
                    name,
                    ProviderConfig::HashiCorpVault {
                        address,
                        path,
                        token,
                    },
                ))
            }
            _ => Err(FnoxError::Config(
                "Unknown secrets manager provider".to_string(),
            )),
        }
    }

    async fn setup_keychain(&self) -> Result<(String, ProviderConfig)> {
        println!("\n🔐 OS Keychain setup:");
        println!("   Uses your operating system's secure keychain");
        println!("   - macOS: Keychain Access");
        println!("   - Windows: Credential Manager");
        println!("   - Linux: Secret Service (GNOME Keyring, KWallet)\n");

        let service = Input::new("Service name (namespace for your secrets):")
            .placeholder("fnox")
            .run()
            .map_err(|e| FnoxError::Config(format!("Wizard cancelled: {}", e)))?;

        let prefix = Input::new("Secret name prefix (optional):")
            .placeholder("myapp/")
            .run()
            .ok()
            .filter(|s| !s.is_empty());

        let name = Input::new("Provider name:")
            .placeholder("keychain")
            .run()
            .unwrap_or_else(|_| "keychain".to_string());

        Ok((name, ProviderConfig::Keychain { service, prefix }))
    }
}
