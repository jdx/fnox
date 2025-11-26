use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::AsRefStr;

pub mod age;
pub mod aws_kms;
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
