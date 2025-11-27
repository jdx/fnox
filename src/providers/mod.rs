use crate::config::ConfigValue;
use crate::config_resolver::ResolutionContext;
use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::AsRefStr;

pub mod age;
pub mod aws_kms;
pub mod aws_ps;
pub mod aws_sm;
pub mod azure_kms;
pub mod azure_sm;
pub mod bitwarden;
pub mod gcp_kms;
pub mod gcp_sm;
pub mod infisical;
pub mod keepass;
pub mod keychain;
pub mod onepassword;
pub mod password_store;
pub mod plain;
pub mod vault;

/// Provider capabilities - what a provider can do
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCapability {
    /// Provider can encrypt/decrypt values locally (stores ciphertext in config)
    Encryption,
    /// Provider stores values remotely (stores only references in config)
    RemoteStorage,
    /// Provider fetches values from a remote source (like 1Password, read-only)
    RemoteRead,
}

/// Category for grouping providers in the wizard
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardCategory {
    Local,
    PasswordManager,
    CloudKms,
    CloudSecretsManager,
    OsKeychain,
}

impl WizardCategory {
    /// Display name for the category
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Local => "Local (easy to start)",
            Self::PasswordManager => "Password Manager",
            Self::CloudKms => "Cloud KMS",
            Self::CloudSecretsManager => "Cloud Secrets Manager",
            Self::OsKeychain => "OS Keychain",
        }
    }

    /// Description for the category
    pub fn description(&self) -> &'static str {
        match self {
            Self::Local => "Plain text or local encryption - no external dependencies",
            Self::PasswordManager => {
                "1Password, Bitwarden, Infisical - use your existing password manager"
            }
            Self::CloudKms => "AWS KMS, Azure Key Vault, GCP KMS - encrypt with cloud keys",
            Self::CloudSecretsManager => {
                "AWS, Azure, GCP, HashiCorp Vault - store secrets remotely"
            }
            Self::OsKeychain => "Use your operating system's secure keychain",
        }
    }

    /// All categories in display order
    pub fn all() -> &'static [WizardCategory] {
        &[
            Self::Local,
            Self::PasswordManager,
            Self::CloudKms,
            Self::CloudSecretsManager,
            Self::OsKeychain,
        ]
    }
}

/// A field that the wizard needs to collect
#[derive(Debug, Clone, Copy)]
pub struct WizardField {
    /// Internal field name (e.g., "region")
    pub name: &'static str,
    /// Prompt shown to user (e.g., "AWS Region:")
    pub label: &'static str,
    /// Placeholder value (e.g., "us-east-1")
    pub placeholder: &'static str,
    /// Whether field must have a value
    pub required: bool,
    /// Whether field contains sensitive data (like tokens/passwords)
    /// Sensitive fields should be stored as secret references, not plain values
    pub sensitive: bool,
    /// Suggested secret name for sensitive fields (e.g., "VAULT_TOKEN")
    /// Used by the wizard to suggest a default when prompting for secret references
    pub default_secret_name: Option<&'static str>,
}

impl WizardField {
    /// Default value for use in const contexts with struct update syntax.
    /// Example: `WizardField { name: "foo", ..WizardField::DEFAULT }`
    pub const DEFAULT: Self = Self {
        name: "",
        label: "",
        placeholder: "",
        required: false,
        sensitive: false,
        default_secret_name: None,
    };
}

impl Default for WizardField {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Complete wizard metadata for a provider type
#[derive(Debug, Clone)]
pub struct WizardInfo {
    /// Provider type identifier (e.g., "aws-sm")
    pub provider_type: &'static str,
    /// Display name (e.g., "AWS Secrets Manager")
    pub display_name: &'static str,
    /// Short description for selection menu
    pub description: &'static str,
    /// Category for grouping
    pub category: WizardCategory,
    /// Multi-line setup instructions
    pub setup_instructions: &'static str,
    /// Default provider name (e.g., "sm")
    pub default_name: &'static str,
    /// Fields to collect from user
    pub fields: &'static [WizardField],
}

#[derive(Debug, Clone, Serialize, Deserialize, AsRefStr)]
#[serde(tag = "type")]
#[serde(deny_unknown_fields)]
pub enum ProviderConfig {
    #[serde(rename = "1password")]
    #[strum(serialize = "1password")]
    OnePassword(onepassword::OnePasswordConfig),
    #[serde(rename = "age")]
    #[strum(serialize = "age")]
    AgeEncryption(age::AgeConfig),
    #[serde(rename = "aws-kms")]
    #[strum(serialize = "aws-kms")]
    AwsKms(aws_kms::AwsKmsConfig),
    #[serde(rename = "aws-sm")]
    #[strum(serialize = "aws-sm")]
    AwsSecretsManager(aws_sm::AwsSmConfig),
    #[serde(rename = "aws-ps")]
    #[strum(serialize = "aws-ps")]
    AwsParameterStore(aws_ps::AwsPsConfig),
    #[serde(rename = "azure-kms")]
    #[strum(serialize = "azure-kms")]
    AzureKms(azure_kms::AzureKmsConfig),
    #[serde(rename = "azure-sm")]
    #[strum(serialize = "azure-sm")]
    AzureSecretsManager(azure_sm::AzureSmConfig),
    #[serde(rename = "bitwarden")]
    #[strum(serialize = "bitwarden")]
    Bitwarden(bitwarden::BitwardenConfig),
    #[serde(rename = "gcp-kms")]
    #[strum(serialize = "gcp-kms")]
    GcpKms(gcp_kms::GcpKmsConfig),
    #[serde(rename = "gcp-sm")]
    #[strum(serialize = "gcp-sm")]
    GoogleSecretManager(gcp_sm::GcpSmConfig),
    #[serde(rename = "infisical")]
    #[strum(serialize = "infisical")]
    Infisical(infisical::InfisicalConfig),
    #[serde(rename = "keepass")]
    #[strum(serialize = "keepass")]
    KeePass(keepass::KeePassConfig),
    #[serde(rename = "keychain")]
    #[strum(serialize = "keychain")]
    Keychain(keychain::KeychainConfig),
    #[serde(rename = "password-store")]
    #[strum(serialize = "password-store")]
    PasswordStore(password_store::PasswordStoreConfig),
    #[serde(rename = "plain")]
    #[strum(serialize = "plain")]
    Plain(plain::PlainConfig),
    #[serde(rename = "vault")]
    #[strum(serialize = "vault")]
    HashiCorpVault(vault::VaultConfig),
}

#[async_trait]
pub trait Provider: Send + Sync {
    /// Get a secret value from the provider (decrypt if needed)
    async fn get_secret(&self, value: &str) -> Result<String>;

    /// Get multiple secrets in a batch (more efficient for some providers)
    ///
    /// Takes a slice of (key, value) tuples where:
    /// - key: the environment variable name (e.g., "MY_SECRET")
    /// - value: the provider-specific reference (e.g., "op://vault/item/field")
    ///
    /// Returns a HashMap of successfully resolved secrets. Failures are logged but don't
    /// stop other secrets from being resolved.
    ///
    /// Default implementation fetches secrets in parallel using tokio tasks.
    /// Providers can override this for true batch operations (e.g., single API call).
    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        use futures::stream::{self, StreamExt};

        // Clone the secrets to avoid lifetime issues with async closures
        let secrets_vec: Vec<_> = secrets.to_vec();

        // Fetch all secrets in parallel (up to 10 concurrent)
        let results: Vec<_> = stream::iter(secrets_vec)
            .map(|(key, value)| async move {
                let result = self.get_secret(&value).await;
                (key, result)
            })
            .buffer_unordered(10)
            .collect()
            .await;

        results.into_iter().collect()
    }

    /// Encrypt a value with this provider (for encryption providers)
    async fn encrypt(&self, _value: &str) -> Result<String> {
        // Default implementation for non-encryption providers
        Err(crate::error::FnoxError::Provider(
            "This provider does not support encryption".to_string(),
        ))
    }

    /// Store a secret and return the value to save in config
    ///
    /// This is a unified method for both encryption and remote storage:
    /// - Encryption providers (age, aws-kms): encrypt the value and return ciphertext
    /// - Remote storage providers (aws-sm, keychain): store remotely and return the key name
    /// - Read-only providers: return an error
    ///
    /// Returns the value that should be stored in the config file.
    async fn put_secret(&self, _key: &str, value: &str) -> Result<String> {
        let capabilities = self.capabilities();

        if capabilities.contains(&ProviderCapability::Encryption) {
            // Encryption provider - encrypt and return ciphertext
            self.encrypt(value).await
        } else if capabilities.contains(&ProviderCapability::RemoteStorage) {
            // Remote storage provider - should override this method
            Err(crate::error::FnoxError::Provider(
                "Remote storage provider must implement put_secret".to_string(),
            ))
        } else {
            // Read-only provider
            Err(crate::error::FnoxError::Provider(
                "This provider does not support storing secrets".to_string(),
            ))
        }
    }

    /// Get the capabilities of this provider
    fn capabilities(&self) -> Vec<ProviderCapability> {
        // Default: read-only remote provider (like 1Password, Bitwarden)
        vec![ProviderCapability::RemoteRead]
    }

    /// Test if the provider is accessible and properly configured
    async fn test_connection(&self) -> Result<()> {
        // Default implementation does a basic check
        Ok(())
    }
}

/// All wizard info collected from provider modules
pub static ALL_WIZARD_INFO: &[&WizardInfo] = &[
    // Local providers
    &plain::WIZARD_INFO,
    &age::WIZARD_INFO,
    &keepass::WIZARD_INFO,
    &password_store::WIZARD_INFO,
    // Password Manager providers
    &onepassword::WIZARD_INFO,
    &bitwarden::WIZARD_INFO,
    &infisical::WIZARD_INFO,
    // Cloud KMS providers
    &aws_kms::WIZARD_INFO,
    &azure_kms::WIZARD_INFO,
    &gcp_kms::WIZARD_INFO,
    // Cloud Secrets Manager providers
    &aws_sm::WIZARD_INFO,
    &aws_ps::WIZARD_INFO,
    &azure_sm::WIZARD_INFO,
    &gcp_sm::WIZARD_INFO,
    &vault::WIZARD_INFO,
    // OS Keychain
    &keychain::WIZARD_INFO,
];

impl ProviderConfig {
    /// Get the provider type name (e.g., "age", "1password", "plain")
    pub fn provider_type(&self) -> &str {
        self.as_ref()
    }

    /// Create a provider, resolving all secret references.
    pub async fn create_provider(
        &self,
        ctx: &mut ResolutionContext<'_>,
    ) -> Result<Box<dyn Provider>> {
        match self {
            Self::OnePassword(c) => c.create_provider(ctx).await,
            Self::AgeEncryption(c) => c.create_provider(ctx).await,
            Self::AwsKms(c) => c.create_provider(ctx).await,
            Self::AwsSecretsManager(c) => c.create_provider(ctx).await,
            Self::AwsParameterStore(c) => c.create_provider(ctx).await,
            Self::AzureKms(c) => c.create_provider(ctx).await,
            Self::AzureSecretsManager(c) => c.create_provider(ctx).await,
            Self::Bitwarden(c) => c.create_provider(ctx).await,
            Self::GcpKms(c) => c.create_provider(ctx).await,
            Self::GoogleSecretManager(c) => c.create_provider(ctx).await,
            Self::Infisical(c) => c.create_provider(ctx).await,
            Self::KeePass(c) => c.create_provider(ctx).await,
            Self::Keychain(c) => c.create_provider(ctx).await,
            Self::PasswordStore(c) => c.create_provider(ctx).await,
            Self::Plain(c) => c.create_provider(ctx).await,
            Self::HashiCorpVault(c) => c.create_provider(ctx).await,
        }
    }

    /// Get wizard info for providers in a specific category
    pub fn wizard_info_by_category(category: WizardCategory) -> Vec<&'static WizardInfo> {
        ALL_WIZARD_INFO
            .iter()
            .filter(|info| info.category == category)
            .copied()
            .collect()
    }

    /// Build a ProviderConfig from wizard field values.
    ///
    /// Fields with the prefix `@secret:` are treated as secret references.
    /// For example, `@secret:VAULT_TOKEN` becomes `{ secret = "VAULT_TOKEN" }`.
    pub fn from_wizard_fields(
        provider_type: &str,
        fields: &HashMap<String, String>,
    ) -> Result<Self> {
        use crate::error::FnoxError;

        // Helper to get a required field as ConfigValue
        let get_required_config = |name: &str| -> Result<ConfigValue> {
            fields
                .get(name)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    if let Some(secret_name) = s.strip_prefix("@secret:") {
                        ConfigValue::SecretRef(crate::config::SecretRef {
                            secret: secret_name.to_string(),
                        })
                    } else {
                        ConfigValue::Plain(s.clone())
                    }
                })
                .ok_or_else(|| FnoxError::Config(format!("{} is required", name)))
        };

        // Helper to get an optional field as ConfigValue
        let get_optional_config = |name: &str| -> Option<ConfigValue> {
            fields.get(name).and_then(|s| {
                if s.is_empty() {
                    None
                } else if let Some(secret_name) = s.strip_prefix("@secret:") {
                    Some(ConfigValue::SecretRef(crate::config::SecretRef {
                        secret: secret_name.to_string(),
                    }))
                } else {
                    Some(ConfigValue::Plain(s.clone()))
                }
            })
        };

        match provider_type {
            "plain" => Ok(ProviderConfig::Plain(plain::PlainConfig {})),
            "age" => Ok(ProviderConfig::AgeEncryption(age::AgeConfig {
                recipients: vec![get_required_config("recipient")?],
                key_file: None,
            })),
            "keepass" => Ok(ProviderConfig::KeePass(keepass::KeePassConfig {
                database: get_required_config("database")?,
                keyfile: get_optional_config("keyfile"),
                password: None, // Always use env var or secret ref
            })),
            "password-store" => Ok(ProviderConfig::PasswordStore(
                password_store::PasswordStoreConfig {
                    prefix: get_optional_config("prefix"),
                    store_dir: get_optional_config("store_dir"),
                    gpg_opts: None,
                },
            )),
            "1password" => Ok(ProviderConfig::OnePassword(
                onepassword::OnePasswordConfig {
                    vault: get_optional_config("vault"),
                    account: get_optional_config("account"),
                },
            )),
            "bitwarden" => Ok(ProviderConfig::Bitwarden(bitwarden::BitwardenConfig {
                collection: get_optional_config("collection"),
                organization_id: get_optional_config("organization_id"),
                profile: get_optional_config("profile"),
                backend: None,
            })),
            "infisical" => Ok(ProviderConfig::Infisical(infisical::InfisicalConfig {
                project_id: get_optional_config("project_id"),
                environment: get_optional_config("environment"),
                path: get_optional_config("path"),
            })),
            "aws-kms" => Ok(ProviderConfig::AwsKms(aws_kms::AwsKmsConfig {
                key_id: get_required_config("key_id")?,
                region: get_required_config("region")?,
            })),
            "azure-kms" => Ok(ProviderConfig::AzureKms(azure_kms::AzureKmsConfig {
                vault_url: get_required_config("vault_url")?,
                key_name: get_required_config("key_name")?,
            })),
            "gcp-kms" => Ok(ProviderConfig::GcpKms(gcp_kms::GcpKmsConfig {
                project: get_required_config("project")?,
                location: get_required_config("location")?,
                keyring: get_required_config("keyring")?,
                key: get_required_config("key")?,
            })),
            "aws-sm" => Ok(ProviderConfig::AwsSecretsManager(aws_sm::AwsSmConfig {
                region: get_required_config("region")?,
                prefix: get_optional_config("prefix"),
            })),
            "aws-ps" => Ok(ProviderConfig::AwsParameterStore(aws_ps::AwsPsConfig {
                region: get_required_config("region")?,
                prefix: get_optional_config("prefix"),
            })),
            "azure-sm" => Ok(ProviderConfig::AzureSecretsManager(
                azure_sm::AzureSmConfig {
                    vault_url: get_required_config("vault_url")?,
                    prefix: get_optional_config("prefix"),
                },
            )),
            "gcp-sm" => Ok(ProviderConfig::GoogleSecretManager(gcp_sm::GcpSmConfig {
                project: get_required_config("project")?,
                prefix: get_optional_config("prefix"),
            })),
            "vault" => Ok(ProviderConfig::HashiCorpVault(vault::VaultConfig {
                address: get_required_config("address")?,
                path: get_optional_config("path"),
                token: get_optional_config("token"),
            })),
            "keychain" => Ok(ProviderConfig::Keychain(keychain::KeychainConfig {
                service: get_required_config("service")?,
                prefix: get_optional_config("prefix"),
            })),
            _ => Err(FnoxError::Config(format!(
                "Unknown provider type: {}",
                provider_type
            ))),
        }
    }

    /// Get the capabilities of this provider type.
    ///
    /// This returns capabilities based on the provider type without instantiating
    /// the provider, making it safe to call even when the config contains
    /// unresolved secret references.
    pub fn capabilities(&self) -> Vec<ProviderCapability> {
        match self {
            ProviderConfig::AgeEncryption(_) => vec![ProviderCapability::Encryption],
            ProviderConfig::AwsKms(_) => vec![ProviderCapability::Encryption],
            ProviderConfig::AzureKms(_) => vec![ProviderCapability::Encryption],
            ProviderConfig::GcpKms(_) => vec![ProviderCapability::Encryption],
            ProviderConfig::Plain(_) => vec![ProviderCapability::Encryption],
            ProviderConfig::AwsSecretsManager(_) => vec![ProviderCapability::RemoteStorage],
            ProviderConfig::AwsParameterStore(_) => vec![ProviderCapability::RemoteStorage],
            ProviderConfig::AzureSecretsManager(_) => vec![ProviderCapability::RemoteStorage],
            ProviderConfig::GoogleSecretManager(_) => vec![ProviderCapability::RemoteStorage],
            ProviderConfig::HashiCorpVault(_) => vec![ProviderCapability::RemoteStorage],
            ProviderConfig::KeePass(_) => vec![ProviderCapability::RemoteStorage],
            ProviderConfig::Keychain(_) => vec![ProviderCapability::RemoteStorage],
            ProviderConfig::PasswordStore(_) => vec![ProviderCapability::RemoteStorage],
            ProviderConfig::OnePassword(_) => vec![ProviderCapability::RemoteRead],
            ProviderConfig::Bitwarden(_) => vec![ProviderCapability::RemoteRead],
            ProviderConfig::Infisical(_) => vec![ProviderCapability::RemoteRead],
        }
    }
}
