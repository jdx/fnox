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

pub use bitwarden::BitwardenBackend;

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
#[derive(Debug, Clone)]
pub struct WizardField {
    /// Internal field name (e.g., "region")
    pub name: &'static str,
    /// Prompt shown to user (e.g., "AWS Region:")
    pub label: &'static str,
    /// Placeholder value (e.g., "us-east-1")
    pub placeholder: &'static str,
    /// Whether field must have a value
    pub required: bool,
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
    OnePassword {
        #[serde(skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        account: Option<String>,
    },
    #[serde(rename = "age")]
    #[strum(serialize = "age")]
    AgeEncryption {
        recipients: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        key_file: Option<String>,
    },
    #[serde(rename = "aws-kms")]
    #[strum(serialize = "aws-kms")]
    AwsKms { key_id: String, region: String },
    #[serde(rename = "aws-sm")]
    #[strum(serialize = "aws-sm")]
    AwsSecretsManager {
        region: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    #[serde(rename = "aws-ps")]
    #[strum(serialize = "aws-ps")]
    AwsParameterStore {
        region: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    #[serde(rename = "azure-kms")]
    #[strum(serialize = "azure-kms")]
    AzureKms { vault_url: String, key_name: String },
    #[serde(rename = "azure-sm")]
    #[strum(serialize = "azure-sm")]
    AzureSecretsManager {
        vault_url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    #[serde(rename = "bitwarden")]
    #[strum(serialize = "bitwarden")]
    Bitwarden {
        #[serde(skip_serializing_if = "Option::is_none")]
        collection: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        organization_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
        #[serde(
            default = "default_bitwarden_backend",
            skip_serializing_if = "is_default_backend"
        )]
        backend: Option<BitwardenBackend>,
    },
    #[serde(rename = "gcp-kms")]
    #[strum(serialize = "gcp-kms")]
    GcpKms {
        project: String,
        location: String,
        keyring: String,
        key: String,
    },
    #[serde(rename = "gcp-sm")]
    #[strum(serialize = "gcp-sm")]
    GoogleSecretManager {
        project: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    #[serde(rename = "infisical")]
    #[strum(serialize = "infisical")]
    Infisical {
        #[serde(skip_serializing_if = "Option::is_none")]
        project_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        environment: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    #[serde(rename = "keepass")]
    #[strum(serialize = "keepass")]
    KeePass {
        database: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        keyfile: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    #[serde(rename = "keychain")]
    #[strum(serialize = "keychain")]
    Keychain {
        service: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    #[serde(rename = "password-store")]
    #[strum(serialize = "password-store")]
    PasswordStore {
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        store_dir: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        gpg_opts: Option<String>,
    },
    #[serde(rename = "plain")]
    #[strum(serialize = "plain")]
    Plain,
    #[serde(rename = "vault")]
    #[strum(serialize = "vault")]
    HashiCorpVault {
        address: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
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

impl ProviderConfig {
    /// Get the provider type name (e.g., "age", "1password", "plain")
    pub fn provider_type(&self) -> &str {
        self.as_ref()
    }

    /// Returns wizard info for all provider types
    pub fn all_wizard_info() -> &'static [WizardInfo] {
        use WizardCategory::*;
        static INFO: &[WizardInfo] = &[
            // === Local providers ===
            WizardInfo {
                provider_type: "plain",
                display_name: "Plain text",
                description: "No encryption - stores values directly in config (not recommended for sensitive data)",
                category: Local,
                setup_instructions: "\
Plain provider stores secrets unencrypted in your config file.
Only use this for non-sensitive values or development.",
                default_name: "plain",
                fields: &[],
            },
            WizardInfo {
                provider_type: "age",
                display_name: "Age encryption",
                description: "Modern encryption tool - encrypts values with age keys",
                category: Local,
                setup_instructions: "\
Age uses public/private key pairs for encryption.
Generate a key with: age-keygen -o ~/.config/fnox/age.txt",
                default_name: "age",
                fields: &[WizardField {
                    name: "recipient",
                    label: "Age public key (recipient):",
                    placeholder: "age1...",
                    required: true,
                }],
            },
            WizardInfo {
                provider_type: "keepass",
                display_name: "KeePass",
                description: "Store secrets in a local KeePass database (.kdbx file)",
                category: Local,
                setup_instructions: "\
Stores secrets in a local KeePass database file (.kdbx).
Set password via FNOX_KEEPASS_PASSWORD or KEEPASS_PASSWORD env var.",
                default_name: "keepass",
                fields: &[
                    WizardField {
                        name: "database",
                        label: "Database path:",
                        placeholder: "~/.config/fnox/secrets.kdbx",
                        required: true,
                    },
                    WizardField {
                        name: "keyfile",
                        label: "Keyfile path (optional, for additional security):",
                        placeholder: "",
                        required: false,
                    },
                ],
            },
            WizardInfo {
                provider_type: "password-store",
                display_name: "Password-Store (pass)",
                description: "GPG-encrypted password store - the standard Unix password manager",
                category: Local,
                setup_instructions: "\
Uses GPG-encrypted files in ~/.password-store/.
Requires: pass CLI and a GPG key configured.
Initialize with: pass init <gpg-key-id>",
                default_name: "pass",
                fields: &[
                    WizardField {
                        name: "prefix",
                        label: "Secret name prefix (optional):",
                        placeholder: "fnox/",
                        required: false,
                    },
                    WizardField {
                        name: "store_dir",
                        label: "Custom store directory (optional):",
                        placeholder: "",
                        required: false,
                    },
                ],
            },
            // === Password Manager providers ===
            WizardInfo {
                provider_type: "1password",
                display_name: "1Password",
                description: "Requires 1Password CLI and service account token",
                category: PasswordManager,
                setup_instructions: "\
Requires: 1Password CLI (op) and a service account token.
Set token: export OP_SERVICE_ACCOUNT_TOKEN=<token>",
                default_name: "onepass",
                fields: &[
                    WizardField {
                        name: "vault",
                        label: "Vault name (optional):",
                        placeholder: "",
                        required: false,
                    },
                    WizardField {
                        name: "account",
                        label: "Account (optional, e.g., my.1password.com):",
                        placeholder: "",
                        required: false,
                    },
                ],
            },
            WizardInfo {
                provider_type: "bitwarden",
                display_name: "Bitwarden",
                description: "Requires Bitwarden CLI and session token",
                category: PasswordManager,
                setup_instructions: "\
Requires: Bitwarden CLI (bw) and session token.
Login: bw login && export BW_SESSION=$(bw unlock --raw)",
                default_name: "bitwarden",
                fields: &[
                    WizardField {
                        name: "collection",
                        label: "Collection ID (optional):",
                        placeholder: "",
                        required: false,
                    },
                    WizardField {
                        name: "organization_id",
                        label: "Organization ID (optional):",
                        placeholder: "",
                        required: false,
                    },
                    WizardField {
                        name: "profile",
                        label: "Bitwarden CLI profile (optional):",
                        placeholder: "",
                        required: false,
                    },
                ],
            },
            WizardInfo {
                provider_type: "infisical",
                display_name: "Infisical",
                description: "Cloud secrets manager with Universal Auth",
                category: PasswordManager,
                setup_instructions: "\
Requires: Infisical CLI and Universal Auth credentials.
Set credentials:
  export INFISICAL_CLIENT_ID=<client-id>
  export INFISICAL_CLIENT_SECRET=<client-secret>",
                default_name: "infisical",
                fields: &[
                    WizardField {
                        name: "project_id",
                        label: "Project ID (optional if CLI is configured):",
                        placeholder: "",
                        required: false,
                    },
                    WizardField {
                        name: "environment",
                        label: "Environment (optional, default: dev):",
                        placeholder: "dev",
                        required: false,
                    },
                    WizardField {
                        name: "path",
                        label: "Secret path (optional, default: /):",
                        placeholder: "/",
                        required: false,
                    },
                ],
            },
            // === Cloud KMS providers ===
            WizardInfo {
                provider_type: "aws-kms",
                display_name: "AWS KMS",
                description: "AWS Key Management Service",
                category: CloudKms,
                setup_instructions: "\
Encrypts secrets using AWS KMS keys.
Requires AWS credentials configured.",
                default_name: "kms",
                fields: &[
                    WizardField {
                        name: "key_id",
                        label: "KMS Key ID (ARN or alias):",
                        placeholder: "arn:aws:kms:us-east-1:123456789012:key/...",
                        required: true,
                    },
                    WizardField {
                        name: "region",
                        label: "AWS Region:",
                        placeholder: "us-east-1",
                        required: true,
                    },
                ],
            },
            WizardInfo {
                provider_type: "azure-kms",
                display_name: "Azure Key Vault",
                description: "Azure Key Vault for encryption",
                category: CloudKms,
                setup_instructions: "\
Encrypts secrets using Azure Key Vault keys.
Requires Azure credentials configured.",
                default_name: "azure-kms",
                fields: &[
                    WizardField {
                        name: "vault_url",
                        label: "Key Vault URL:",
                        placeholder: "https://my-vault.vault.azure.net/",
                        required: true,
                    },
                    WizardField {
                        name: "key_name",
                        label: "Key name:",
                        placeholder: "my-key",
                        required: true,
                    },
                ],
            },
            WizardInfo {
                provider_type: "gcp-kms",
                display_name: "GCP KMS",
                description: "Google Cloud Key Management Service",
                category: CloudKms,
                setup_instructions: "\
Encrypts secrets using Google Cloud KMS.
Requires GCP credentials configured.",
                default_name: "gcp-kms",
                fields: &[
                    WizardField {
                        name: "project",
                        label: "GCP Project ID:",
                        placeholder: "my-project",
                        required: true,
                    },
                    WizardField {
                        name: "location",
                        label: "Location:",
                        placeholder: "us-east1",
                        required: true,
                    },
                    WizardField {
                        name: "keyring",
                        label: "Keyring name:",
                        placeholder: "my-keyring",
                        required: true,
                    },
                    WizardField {
                        name: "key",
                        label: "Key name:",
                        placeholder: "my-key",
                        required: true,
                    },
                ],
            },
            // === Cloud Secrets Manager providers ===
            WizardInfo {
                provider_type: "aws-sm",
                display_name: "AWS Secrets Manager",
                description: "AWS Secrets Manager",
                category: CloudSecretsManager,
                setup_instructions: "\
Stores secrets in AWS Secrets Manager.
Requires AWS credentials configured.",
                default_name: "sm",
                fields: &[
                    WizardField {
                        name: "region",
                        label: "AWS Region:",
                        placeholder: "us-east-1",
                        required: true,
                    },
                    WizardField {
                        name: "prefix",
                        label: "Secret name prefix (optional):",
                        placeholder: "fnox/",
                        required: false,
                    },
                ],
            },
            WizardInfo {
                provider_type: "aws-ps",
                display_name: "AWS Parameter Store",
                description: "AWS Systems Manager Parameter Store",
                category: CloudSecretsManager,
                setup_instructions: "\
Stores secrets in AWS Systems Manager Parameter Store.
Uses SecureString parameters for encryption.
Requires AWS credentials configured.",
                default_name: "ps",
                fields: &[
                    WizardField {
                        name: "region",
                        label: "AWS Region:",
                        placeholder: "us-east-1",
                        required: true,
                    },
                    WizardField {
                        name: "prefix",
                        label: "Parameter path prefix (optional):",
                        placeholder: "/myapp/prod/",
                        required: false,
                    },
                ],
            },
            WizardInfo {
                provider_type: "azure-sm",
                display_name: "Azure Key Vault Secrets",
                description: "Azure Key Vault secret storage",
                category: CloudSecretsManager,
                setup_instructions: "\
Stores secrets in Azure Key Vault.
Requires Azure credentials configured.",
                default_name: "azure-sm",
                fields: &[
                    WizardField {
                        name: "vault_url",
                        label: "Key Vault URL:",
                        placeholder: "https://my-vault.vault.azure.net/",
                        required: true,
                    },
                    WizardField {
                        name: "prefix",
                        label: "Secret name prefix (optional):",
                        placeholder: "fnox-",
                        required: false,
                    },
                ],
            },
            WizardInfo {
                provider_type: "gcp-sm",
                display_name: "GCP Secret Manager",
                description: "Google Cloud Secret Manager",
                category: CloudSecretsManager,
                setup_instructions: "\
Stores secrets in Google Cloud Secret Manager.
Requires GCP credentials configured.",
                default_name: "gcp-sm",
                fields: &[
                    WizardField {
                        name: "project",
                        label: "GCP Project ID:",
                        placeholder: "my-project",
                        required: true,
                    },
                    WizardField {
                        name: "prefix",
                        label: "Secret name prefix (optional):",
                        placeholder: "fnox-",
                        required: false,
                    },
                ],
            },
            WizardInfo {
                provider_type: "vault",
                display_name: "HashiCorp Vault",
                description: "HashiCorp Vault",
                category: CloudSecretsManager,
                setup_instructions: "\
Stores secrets in HashiCorp Vault.
Requires Vault address and token.",
                default_name: "vault",
                fields: &[
                    WizardField {
                        name: "address",
                        label: "Vault address:",
                        placeholder: "https://vault.example.com:8200",
                        required: true,
                    },
                    WizardField {
                        name: "path",
                        label: "Vault path prefix (optional):",
                        placeholder: "secret/data/fnox",
                        required: false,
                    },
                    WizardField {
                        name: "token",
                        label: "Vault token (optional, can use VAULT_TOKEN env var):",
                        placeholder: "",
                        required: false,
                    },
                ],
            },
            // === OS Keychain ===
            WizardInfo {
                provider_type: "keychain",
                display_name: "OS Keychain",
                description: "Use your operating system's secure keychain",
                category: OsKeychain,
                setup_instructions: "\
Uses your operating system's secure keychain:
  - macOS: Keychain Access
  - Windows: Credential Manager
  - Linux: Secret Service (GNOME Keyring, KWallet)",
                default_name: "keychain",
                fields: &[
                    WizardField {
                        name: "service",
                        label: "Service name (namespace for your secrets):",
                        placeholder: "fnox",
                        required: true,
                    },
                    WizardField {
                        name: "prefix",
                        label: "Secret name prefix (optional):",
                        placeholder: "myapp/",
                        required: false,
                    },
                ],
            },
        ];
        INFO
    }

    /// Get wizard info for providers in a specific category
    pub fn wizard_info_by_category(category: WizardCategory) -> Vec<&'static WizardInfo> {
        Self::all_wizard_info()
            .iter()
            .filter(|info| info.category == category)
            .collect()
    }

    /// Build a ProviderConfig from wizard field values
    pub fn from_wizard_fields(
        provider_type: &str,
        fields: &HashMap<String, String>,
    ) -> Result<Self> {
        use crate::error::FnoxError;

        // Helper to get a required field
        let get_required = |name: &str| -> Result<String> {
            fields
                .get(name)
                .filter(|s| !s.is_empty())
                .cloned()
                .ok_or_else(|| FnoxError::Config(format!("{} is required", name)))
        };

        // Helper to get an optional field
        let get_optional =
            |name: &str| -> Option<String> { fields.get(name).filter(|s| !s.is_empty()).cloned() };

        match provider_type {
            "plain" => Ok(ProviderConfig::Plain),
            "age" => Ok(ProviderConfig::AgeEncryption {
                recipients: vec![get_required("recipient")?],
                key_file: None,
            }),
            "keepass" => Ok(ProviderConfig::KeePass {
                database: get_required("database")?,
                keyfile: get_optional("keyfile"),
                password: None, // Always use env var
            }),
            "password-store" => Ok(ProviderConfig::PasswordStore {
                prefix: get_optional("prefix"),
                store_dir: get_optional("store_dir"),
                gpg_opts: None,
            }),
            "1password" => Ok(ProviderConfig::OnePassword {
                vault: get_optional("vault"),
                account: get_optional("account"),
            }),
            "bitwarden" => Ok(ProviderConfig::Bitwarden {
                collection: get_optional("collection"),
                organization_id: get_optional("organization_id"),
                profile: get_optional("profile"),
                backend: None,
            }),
            "infisical" => Ok(ProviderConfig::Infisical {
                project_id: get_optional("project_id"),
                environment: get_optional("environment"),
                path: get_optional("path"),
            }),
            "aws-kms" => Ok(ProviderConfig::AwsKms {
                key_id: get_required("key_id")?,
                region: get_required("region")?,
            }),
            "azure-kms" => Ok(ProviderConfig::AzureKms {
                vault_url: get_required("vault_url")?,
                key_name: get_required("key_name")?,
            }),
            "gcp-kms" => Ok(ProviderConfig::GcpKms {
                project: get_required("project")?,
                location: get_required("location")?,
                keyring: get_required("keyring")?,
                key: get_required("key")?,
            }),
            "aws-sm" => Ok(ProviderConfig::AwsSecretsManager {
                region: get_required("region")?,
                prefix: get_optional("prefix"),
            }),
            "aws-ps" => Ok(ProviderConfig::AwsParameterStore {
                region: get_required("region")?,
                prefix: get_optional("prefix"),
            }),
            "azure-sm" => Ok(ProviderConfig::AzureSecretsManager {
                vault_url: get_required("vault_url")?,
                prefix: get_optional("prefix"),
            }),
            "gcp-sm" => Ok(ProviderConfig::GoogleSecretManager {
                project: get_required("project")?,
                prefix: get_optional("prefix"),
            }),
            "vault" => Ok(ProviderConfig::HashiCorpVault {
                address: get_required("address")?,
                path: get_optional("path"),
                token: get_optional("token"),
            }),
            "keychain" => Ok(ProviderConfig::Keychain {
                service: get_required("service")?,
                prefix: get_optional("prefix"),
            }),
            _ => Err(FnoxError::Config(format!(
                "Unknown provider type: {}",
                provider_type
            ))),
        }
    }
}

/// Create a provider from a provider configuration
pub fn get_provider(config: &ProviderConfig) -> Result<Box<dyn Provider>> {
    match config {
        ProviderConfig::OnePassword { vault, account } => Ok(Box::new(
            onepassword::OnePasswordProvider::new(vault.clone(), account.clone()),
        )),
        ProviderConfig::AgeEncryption {
            recipients,
            key_file,
        } => Ok(Box::new(age::AgeEncryptionProvider::new(
            recipients.clone(),
            key_file.clone(),
        ))),
        ProviderConfig::AwsKms { key_id, region } => Ok(Box::new(aws_kms::AwsKmsProvider::new(
            key_id.clone(),
            region.clone(),
        ))),
        ProviderConfig::AwsSecretsManager { region, prefix } => Ok(Box::new(
            aws_sm::AwsSecretsManagerProvider::new(region.clone(), prefix.clone()),
        )),
        ProviderConfig::AwsParameterStore { region, prefix } => Ok(Box::new(
            aws_ps::AwsParameterStoreProvider::new(region.clone(), prefix.clone()),
        )),
        ProviderConfig::AzureKms {
            vault_url,
            key_name,
        } => Ok(Box::new(azure_kms::AzureKeyVaultProvider::new(
            vault_url.clone(),
            key_name.clone(),
        ))),
        ProviderConfig::AzureSecretsManager { vault_url, prefix } => Ok(Box::new(
            azure_sm::AzureSecretsManagerProvider::new(vault_url.clone(), prefix.clone()),
        )),
        ProviderConfig::Bitwarden {
            collection,
            organization_id,
            profile,
            backend,
        } => Ok(Box::new(bitwarden::BitwardenProvider::new(
            collection.clone(),
            organization_id.clone(),
            profile.clone(),
            *backend,
        ))),
        ProviderConfig::GcpKms {
            project,
            location,
            keyring,
            key,
        } => Ok(Box::new(gcp_kms::GcpKmsProvider::new(
            project.clone(),
            location.clone(),
            keyring.clone(),
            key.clone(),
        ))),
        ProviderConfig::GoogleSecretManager { project, prefix } => Ok(Box::new(
            gcp_sm::GoogleSecretManagerProvider::new(project.clone(), prefix.clone()),
        )),
        ProviderConfig::Infisical {
            project_id,
            environment,
            path,
        } => Ok(Box::new(infisical::InfisicalProvider::new(
            project_id.clone(),
            environment.clone(),
            path.clone(),
        ))),
        ProviderConfig::KeePass {
            database,
            keyfile,
            password,
        } => Ok(Box::new(keepass::KeePassProvider::new(
            database.clone(),
            keyfile.clone(),
            password.clone(),
        ))),
        ProviderConfig::Keychain { service, prefix } => Ok(Box::new(
            keychain::KeychainProvider::new(service.clone(), prefix.clone()),
        )),
        ProviderConfig::PasswordStore {
            prefix,
            store_dir,
            gpg_opts,
        } => Ok(Box::new(password_store::PasswordStoreProvider::new(
            prefix.clone(),
            store_dir.clone(),
            gpg_opts.clone(),
        ))),
        ProviderConfig::Plain => Ok(Box::new(plain::PlainProvider::new())),
        ProviderConfig::HashiCorpVault {
            address,
            path,
            token,
        } => Ok(Box::new(vault::HashiCorpVaultProvider::new(
            address.clone(),
            path.clone(),
            token.clone(),
        ))),
    }
}

fn default_bitwarden_backend() -> Option<BitwardenBackend> {
    Some(BitwardenBackend::Bw)
}

fn is_default_backend(backend: &Option<BitwardenBackend>) -> bool {
    backend.as_ref().is_none_or(|b| *b == BitwardenBackend::Bw)
}
