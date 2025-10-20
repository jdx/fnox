use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;
use strum::AsRefStr;

pub mod age;
pub mod aws_kms;
pub mod aws_sm;
pub mod azure_kms;
pub mod azure_sm;
pub mod bitwarden;
pub mod gcp_kms;
pub mod gcp_sm;
pub mod keychain;
pub mod onepassword;
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

#[derive(Debug, Clone, Serialize, Deserialize, AsRefStr)]
#[serde(tag = "type")]
#[serde(deny_unknown_fields)]
pub enum ProviderConfig {
    #[serde(rename = "1password")]
    #[strum(serialize = "1password")]
    OnePassword {
        vault: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        account: Option<String>,
    },
    #[serde(rename = "bitwarden")]
    #[strum(serialize = "bitwarden")]
    Bitwarden {
        #[serde(skip_serializing_if = "Option::is_none")]
        collection: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        organization_id: Option<String>,
    },
    #[serde(rename = "aws-sm")]
    #[strum(serialize = "aws-sm")]
    AwsSecretsManager {
        region: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    #[serde(rename = "vault")]
    #[strum(serialize = "vault")]
    HashiCorpVault {
        address: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    #[serde(rename = "gcp-sm")]
    #[strum(serialize = "gcp-sm")]
    GoogleSecretManager {
        project: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    #[serde(rename = "age")]
    #[strum(serialize = "age")]
    AgeEncryption { recipients: Vec<String> },
    #[serde(rename = "aws-kms")]
    #[strum(serialize = "aws-kms")]
    AwsKms { key_id: String, region: String },
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
    #[serde(rename = "gcp-kms")]
    #[strum(serialize = "gcp-kms")]
    GcpKms {
        project: String,
        location: String,
        keyring: String,
        key: String,
    },
    #[serde(rename = "keychain")]
    #[strum(serialize = "keychain")]
    Keychain {
        service: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    #[serde(rename = "plain")]
    #[strum(serialize = "plain")]
    Plain,
}

#[async_trait]
pub trait Provider: Send + Sync {
    /// Get a secret value from the provider (decrypt if needed)
    async fn get_secret(&self, value: &str, key_file: Option<&Path>) -> Result<String>;

    /// Encrypt a value with this provider (for encryption providers)
    async fn encrypt(&self, _value: &str, _key_file: Option<&Path>) -> Result<String> {
        // Default implementation for non-encryption providers
        Err(crate::error::FnoxError::Provider(
            "This provider does not support encryption".to_string(),
        ))
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
        ProviderConfig::Bitwarden {
            collection,
            organization_id,
        } => Ok(Box::new(bitwarden::BitwardenProvider::new(
            collection.clone(),
            organization_id.clone(),
        ))),
        ProviderConfig::AwsSecretsManager { region, prefix } => Ok(Box::new(
            aws_sm::AwsSecretsManagerProvider::new(region.clone(), prefix.clone()),
        )),
        ProviderConfig::HashiCorpVault {
            address,
            path,
            token,
        } => Ok(Box::new(vault::HashiCorpVaultProvider::new(
            address.clone(),
            path.clone(),
            token.clone(),
        ))),
        ProviderConfig::GoogleSecretManager { project, prefix } => Ok(Box::new(
            gcp_sm::GoogleSecretManagerProvider::new(project.clone(), prefix.clone()),
        )),
        ProviderConfig::AgeEncryption { recipients } => Ok(Box::new(
            age::AgeEncryptionProvider::new(recipients.clone()),
        )),
        ProviderConfig::AwsKms { key_id, region } => Ok(Box::new(aws_kms::AwsKmsProvider::new(
            key_id.clone(),
            region.clone(),
        ))),
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
        ProviderConfig::Keychain { service, prefix } => Ok(Box::new(
            keychain::KeychainProvider::new(service.clone(), prefix.clone()),
        )),
        ProviderConfig::Plain => Ok(Box::new(plain::PlainProvider::new())),
    }
}
