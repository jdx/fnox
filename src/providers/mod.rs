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
pub mod resolved;
pub mod resolver;
pub mod secret_ref;
pub mod vault;

pub use bitwarden::BitwardenBackend;
pub use resolved::ResolvedProviderConfig;
pub use resolver::resolve_provider_config;
pub use secret_ref::{OptionStringOrSecretRef, StringOrSecretRef};

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
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        vault: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        account: OptionStringOrSecretRef,
    },
    #[serde(rename = "age")]
    #[strum(serialize = "age")]
    AgeEncryption {
        recipients: Vec<String>,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        key_file: OptionStringOrSecretRef,
    },
    #[serde(rename = "aws-kms")]
    #[strum(serialize = "aws-kms")]
    AwsKms {
        key_id: StringOrSecretRef,
        region: StringOrSecretRef,
    },
    #[serde(rename = "aws-sm")]
    #[strum(serialize = "aws-sm")]
    AwsSecretsManager {
        region: StringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        prefix: OptionStringOrSecretRef,
    },
    #[serde(rename = "aws-ps")]
    #[strum(serialize = "aws-ps")]
    AwsParameterStore {
        region: StringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        prefix: OptionStringOrSecretRef,
    },
    #[serde(rename = "azure-kms")]
    #[strum(serialize = "azure-kms")]
    AzureKms {
        vault_url: StringOrSecretRef,
        key_name: StringOrSecretRef,
    },
    #[serde(rename = "azure-sm")]
    #[strum(serialize = "azure-sm")]
    AzureSecretsManager {
        vault_url: StringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        prefix: OptionStringOrSecretRef,
    },
    #[serde(rename = "bitwarden")]
    #[strum(serialize = "bitwarden")]
    Bitwarden {
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        collection: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        organization_id: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        profile: OptionStringOrSecretRef,
        #[serde(
            default = "default_bitwarden_backend",
            skip_serializing_if = "is_default_backend"
        )]
        backend: Option<BitwardenBackend>,
    },
    #[serde(rename = "gcp-kms")]
    #[strum(serialize = "gcp-kms")]
    GcpKms {
        project: StringOrSecretRef,
        location: StringOrSecretRef,
        keyring: StringOrSecretRef,
        key: StringOrSecretRef,
    },
    #[serde(rename = "gcp-sm")]
    #[strum(serialize = "gcp-sm")]
    GoogleSecretManager {
        project: StringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        prefix: OptionStringOrSecretRef,
    },
    #[serde(rename = "infisical")]
    #[strum(serialize = "infisical")]
    Infisical {
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        project_id: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        environment: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        path: OptionStringOrSecretRef,
    },
    #[serde(rename = "keepass")]
    #[strum(serialize = "keepass")]
    KeePass {
        database: StringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        keyfile: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        password: OptionStringOrSecretRef,
    },
    #[serde(rename = "keychain")]
    #[strum(serialize = "keychain")]
    Keychain {
        service: StringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        prefix: OptionStringOrSecretRef,
    },
    #[serde(rename = "password-store")]
    #[strum(serialize = "password-store")]
    PasswordStore {
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        prefix: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        store_dir: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        gpg_opts: OptionStringOrSecretRef,
    },
    #[serde(rename = "plain")]
    #[strum(serialize = "plain")]
    Plain,
    #[serde(rename = "vault")]
    #[strum(serialize = "vault")]
    HashiCorpVault {
        address: StringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        path: OptionStringOrSecretRef,
        #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
        token: OptionStringOrSecretRef,
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

    /// Get wizard info for providers in a specific category
    pub fn wizard_info_by_category(category: WizardCategory) -> Vec<&'static WizardInfo> {
        ALL_WIZARD_INFO
            .iter()
            .filter(|info| info.category == category)
            .copied()
            .collect()
    }

    /// Check if this config has any secret references that need resolution.
    ///
    /// Returns true if any field contains a `{ secret = "..." }` reference.
    pub fn has_secret_refs(&self) -> bool {
        match self {
            Self::Plain => false,
            Self::OnePassword { vault, account } => {
                vault.has_secret_ref() || account.has_secret_ref()
            }
            Self::AgeEncryption { key_file, .. } => key_file.has_secret_ref(),
            Self::AwsKms { key_id, region } => key_id.is_secret_ref() || region.is_secret_ref(),
            Self::AwsSecretsManager { region, prefix } => {
                region.is_secret_ref() || prefix.has_secret_ref()
            }
            Self::AwsParameterStore { region, prefix } => {
                region.is_secret_ref() || prefix.has_secret_ref()
            }
            Self::AzureKms {
                vault_url,
                key_name,
            } => vault_url.is_secret_ref() || key_name.is_secret_ref(),
            Self::AzureSecretsManager { vault_url, prefix } => {
                vault_url.is_secret_ref() || prefix.has_secret_ref()
            }
            Self::Bitwarden {
                collection,
                organization_id,
                profile,
                ..
            } => {
                collection.has_secret_ref()
                    || organization_id.has_secret_ref()
                    || profile.has_secret_ref()
            }
            Self::GcpKms {
                project,
                location,
                keyring,
                key,
            } => {
                project.is_secret_ref()
                    || location.is_secret_ref()
                    || keyring.is_secret_ref()
                    || key.is_secret_ref()
            }
            Self::GoogleSecretManager { project, prefix } => {
                project.is_secret_ref() || prefix.has_secret_ref()
            }
            Self::Infisical {
                project_id,
                environment,
                path,
            } => {
                project_id.has_secret_ref() || environment.has_secret_ref() || path.has_secret_ref()
            }
            Self::KeePass {
                database,
                keyfile,
                password,
            } => database.is_secret_ref() || keyfile.has_secret_ref() || password.has_secret_ref(),
            Self::Keychain { service, prefix } => {
                service.is_secret_ref() || prefix.has_secret_ref()
            }
            Self::PasswordStore {
                prefix,
                store_dir,
                gpg_opts,
            } => prefix.has_secret_ref() || store_dir.has_secret_ref() || gpg_opts.has_secret_ref(),
            Self::HashiCorpVault {
                address,
                path,
                token,
            } => address.is_secret_ref() || path.has_secret_ref() || token.has_secret_ref(),
        }
    }

    /// Convert to ResolvedProviderConfig if all values are literals.
    ///
    /// This is useful when you know all values are literals (e.g., from wizard input)
    /// and don't need async resolution. Returns an error if any field is a secret reference.
    pub fn try_to_resolved(&self) -> Result<ResolvedProviderConfig> {
        use crate::error::FnoxError;

        // Helper to extract literal from required field
        let req = |v: &StringOrSecretRef| -> Result<String> {
            v.as_literal().map(String::from).ok_or_else(|| {
                FnoxError::Config(
                    "Cannot resolve secret reference without config context".to_string(),
                )
            })
        };

        // Helper to extract literal from optional field
        let opt = |v: &OptionStringOrSecretRef| -> Result<Option<String>> {
            match v.as_ref() {
                None => Ok(None),
                Some(inner) => inner
                    .as_literal()
                    .map(|s| Some(s.to_string()))
                    .ok_or_else(|| {
                        FnoxError::Config(
                            "Cannot resolve secret reference without config context".to_string(),
                        )
                    }),
            }
        };

        match self {
            Self::Plain => Ok(ResolvedProviderConfig::Plain),
            Self::OnePassword { vault, account } => Ok(ResolvedProviderConfig::OnePassword {
                vault: opt(vault)?,
                account: opt(account)?,
            }),
            Self::AgeEncryption {
                recipients,
                key_file,
            } => Ok(ResolvedProviderConfig::AgeEncryption {
                recipients: recipients.clone(),
                key_file: opt(key_file)?,
            }),
            Self::AwsKms { key_id, region } => Ok(ResolvedProviderConfig::AwsKms {
                key_id: req(key_id)?,
                region: req(region)?,
            }),
            Self::AwsSecretsManager { region, prefix } => {
                Ok(ResolvedProviderConfig::AwsSecretsManager {
                    region: req(region)?,
                    prefix: opt(prefix)?,
                })
            }
            Self::AwsParameterStore { region, prefix } => {
                Ok(ResolvedProviderConfig::AwsParameterStore {
                    region: req(region)?,
                    prefix: opt(prefix)?,
                })
            }
            Self::AzureKms {
                vault_url,
                key_name,
            } => Ok(ResolvedProviderConfig::AzureKms {
                vault_url: req(vault_url)?,
                key_name: req(key_name)?,
            }),
            Self::AzureSecretsManager { vault_url, prefix } => {
                Ok(ResolvedProviderConfig::AzureSecretsManager {
                    vault_url: req(vault_url)?,
                    prefix: opt(prefix)?,
                })
            }
            Self::Bitwarden {
                collection,
                organization_id,
                profile,
                backend,
            } => Ok(ResolvedProviderConfig::Bitwarden {
                collection: opt(collection)?,
                organization_id: opt(organization_id)?,
                profile: opt(profile)?,
                backend: *backend,
            }),
            Self::GcpKms {
                project,
                location,
                keyring,
                key,
            } => Ok(ResolvedProviderConfig::GcpKms {
                project: req(project)?,
                location: req(location)?,
                keyring: req(keyring)?,
                key: req(key)?,
            }),
            Self::GoogleSecretManager { project, prefix } => {
                Ok(ResolvedProviderConfig::GoogleSecretManager {
                    project: req(project)?,
                    prefix: opt(prefix)?,
                })
            }
            Self::Infisical {
                project_id,
                environment,
                path,
            } => Ok(ResolvedProviderConfig::Infisical {
                project_id: opt(project_id)?,
                environment: opt(environment)?,
                path: opt(path)?,
            }),
            Self::KeePass {
                database,
                keyfile,
                password,
            } => Ok(ResolvedProviderConfig::KeePass {
                database: req(database)?,
                keyfile: opt(keyfile)?,
                password: opt(password)?,
            }),
            Self::Keychain { service, prefix } => Ok(ResolvedProviderConfig::Keychain {
                service: req(service)?,
                prefix: opt(prefix)?,
            }),
            Self::PasswordStore {
                prefix,
                store_dir,
                gpg_opts,
            } => Ok(ResolvedProviderConfig::PasswordStore {
                prefix: opt(prefix)?,
                store_dir: opt(store_dir)?,
                gpg_opts: opt(gpg_opts)?,
            }),
            Self::HashiCorpVault {
                address,
                path,
                token,
            } => Ok(ResolvedProviderConfig::HashiCorpVault {
                address: req(address)?,
                path: opt(path)?,
                token: opt(token)?,
            }),
        }
    }

    /// Build a ProviderConfig from wizard field values
    pub fn from_wizard_fields(
        provider_type: &str,
        fields: &HashMap<String, String>,
    ) -> Result<Self> {
        use crate::error::FnoxError;

        // Helper to get a required field as StringOrSecretRef
        let get_required = |name: &str| -> Result<StringOrSecretRef> {
            fields
                .get(name)
                .filter(|s| !s.is_empty())
                .map(|s| StringOrSecretRef::Literal(s.clone()))
                .ok_or_else(|| FnoxError::Config(format!("{} is required", name)))
        };

        // Helper to get an optional field as OptionStringOrSecretRef
        let get_optional = |name: &str| -> OptionStringOrSecretRef {
            fields
                .get(name)
                .filter(|s| !s.is_empty())
                .map(|s| OptionStringOrSecretRef::literal(s.clone()))
                .unwrap_or_default()
        };

        match provider_type {
            "plain" => Ok(ProviderConfig::Plain),
            "age" => Ok(ProviderConfig::AgeEncryption {
                recipients: vec![
                    fields
                        .get("recipient")
                        .filter(|s| !s.is_empty())
                        .cloned()
                        .ok_or_else(|| FnoxError::Config("recipient is required".to_string()))?,
                ],
                key_file: OptionStringOrSecretRef::none(),
            }),
            "keepass" => Ok(ProviderConfig::KeePass {
                database: get_required("database")?,
                keyfile: get_optional("keyfile"),
                password: OptionStringOrSecretRef::none(), // Always use env var
            }),
            "password-store" => Ok(ProviderConfig::PasswordStore {
                prefix: get_optional("prefix"),
                store_dir: get_optional("store_dir"),
                gpg_opts: OptionStringOrSecretRef::none(),
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

/// Create a provider from a resolved provider configuration.
///
/// This function requires a `ResolvedProviderConfig` where all secret references
/// have been resolved to their actual values. Use `resolve_provider_config` to
/// convert a `ProviderConfig` with potential secret references.
pub fn get_provider_from_resolved(config: &ResolvedProviderConfig) -> Result<Box<dyn Provider>> {
    match config {
        ResolvedProviderConfig::OnePassword { vault, account } => Ok(Box::new(
            onepassword::OnePasswordProvider::new(vault.clone(), account.clone()),
        )),
        ResolvedProviderConfig::AgeEncryption {
            recipients,
            key_file,
        } => Ok(Box::new(age::AgeEncryptionProvider::new(
            recipients.clone(),
            key_file.clone(),
        ))),
        ResolvedProviderConfig::AwsKms { key_id, region } => Ok(Box::new(
            aws_kms::AwsKmsProvider::new(key_id.clone(), region.clone()),
        )),
        ResolvedProviderConfig::AwsSecretsManager { region, prefix } => Ok(Box::new(
            aws_sm::AwsSecretsManagerProvider::new(region.clone(), prefix.clone()),
        )),
        ResolvedProviderConfig::AwsParameterStore { region, prefix } => Ok(Box::new(
            aws_ps::AwsParameterStoreProvider::new(region.clone(), prefix.clone()),
        )),
        ResolvedProviderConfig::AzureKms {
            vault_url,
            key_name,
        } => Ok(Box::new(azure_kms::AzureKeyVaultProvider::new(
            vault_url.clone(),
            key_name.clone(),
        ))),
        ResolvedProviderConfig::AzureSecretsManager { vault_url, prefix } => Ok(Box::new(
            azure_sm::AzureSecretsManagerProvider::new(vault_url.clone(), prefix.clone()),
        )),
        ResolvedProviderConfig::Bitwarden {
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
        ResolvedProviderConfig::GcpKms {
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
        ResolvedProviderConfig::GoogleSecretManager { project, prefix } => Ok(Box::new(
            gcp_sm::GoogleSecretManagerProvider::new(project.clone(), prefix.clone()),
        )),
        ResolvedProviderConfig::Infisical {
            project_id,
            environment,
            path,
        } => Ok(Box::new(infisical::InfisicalProvider::new(
            project_id.clone(),
            environment.clone(),
            path.clone(),
        ))),
        ResolvedProviderConfig::KeePass {
            database,
            keyfile,
            password,
        } => Ok(Box::new(keepass::KeePassProvider::new(
            database.clone(),
            keyfile.clone(),
            password.clone(),
        ))),
        ResolvedProviderConfig::Keychain { service, prefix } => Ok(Box::new(
            keychain::KeychainProvider::new(service.clone(), prefix.clone()),
        )),
        ResolvedProviderConfig::PasswordStore {
            prefix,
            store_dir,
            gpg_opts,
        } => Ok(Box::new(password_store::PasswordStoreProvider::new(
            prefix.clone(),
            store_dir.clone(),
            gpg_opts.clone(),
        ))),
        ResolvedProviderConfig::Plain => Ok(Box::new(plain::PlainProvider::new())),
        ResolvedProviderConfig::HashiCorpVault {
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

/// Create a provider from an unresolved provider configuration.
///
/// This is a convenience wrapper that first resolves any secret references in the
/// configuration (using the provided config and profile), then creates the provider.
///
/// For providers that don't have any secret references, this is equivalent to calling
/// `get_provider_from_resolved` directly with a resolved config.
pub async fn get_provider_resolved(
    config: &crate::config::Config,
    profile: &str,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> Result<Box<dyn Provider>> {
    let resolved = resolve_provider_config(config, profile, provider_name, provider_config).await?;
    get_provider_from_resolved(&resolved)
}

fn default_bitwarden_backend() -> Option<BitwardenBackend> {
    Some(BitwardenBackend::Bw)
}

fn is_default_backend(backend: &Option<BitwardenBackend>) -> bool {
    backend.as_ref().is_none_or(|b| *b == BitwardenBackend::Bw)
}
