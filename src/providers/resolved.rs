//! Resolved provider configuration types.
//!
//! This module contains the `ResolvedProviderConfig` enum which mirrors `ProviderConfig`
//! but with all secret references resolved to their actual string values.
//!
//! The resolution process converts `ProviderConfig` -> `ResolvedProviderConfig` by
//! looking up any `{ secret = "NAME" }` references in the config secrets or environment.

use super::BitwardenBackend;

/// A provider configuration with all secret references resolved to actual values.
///
/// This is the "runtime" version of `ProviderConfig` that can be used to instantiate
/// providers. All fields that could have been secret references are now plain strings.
#[derive(Debug, Clone)]
pub enum ResolvedProviderConfig {
    OnePassword {
        vault: Option<String>,
        account: Option<String>,
    },
    AgeEncryption {
        recipients: Vec<String>,
        key_file: Option<String>,
    },
    AwsKms {
        key_id: String,
        region: String,
    },
    AwsSecretsManager {
        region: String,
        prefix: Option<String>,
    },
    AwsParameterStore {
        region: String,
        prefix: Option<String>,
    },
    AzureKms {
        vault_url: String,
        key_name: String,
    },
    AzureSecretsManager {
        vault_url: String,
        prefix: Option<String>,
    },
    Bitwarden {
        collection: Option<String>,
        organization_id: Option<String>,
        profile: Option<String>,
        backend: Option<BitwardenBackend>,
    },
    GcpKms {
        project: String,
        location: String,
        keyring: String,
        key: String,
    },
    GoogleSecretManager {
        project: String,
        prefix: Option<String>,
    },
    Infisical {
        project_id: Option<String>,
        environment: Option<String>,
        path: Option<String>,
    },
    KeePass {
        database: String,
        keyfile: Option<String>,
        password: Option<String>,
    },
    Keychain {
        service: String,
        prefix: Option<String>,
    },
    PasswordStore {
        prefix: Option<String>,
        store_dir: Option<String>,
        gpg_opts: Option<String>,
    },
    Plain,
    HashiCorpVault {
        address: String,
        path: Option<String>,
        token: Option<String>,
    },
}

impl ResolvedProviderConfig {
    /// Get the provider type name (e.g., "age", "1password", "plain")
    pub fn provider_type(&self) -> &'static str {
        match self {
            Self::OnePassword { .. } => "1password",
            Self::AgeEncryption { .. } => "age",
            Self::AwsKms { .. } => "aws-kms",
            Self::AwsSecretsManager { .. } => "aws-sm",
            Self::AwsParameterStore { .. } => "aws-ps",
            Self::AzureKms { .. } => "azure-kms",
            Self::AzureSecretsManager { .. } => "azure-sm",
            Self::Bitwarden { .. } => "bitwarden",
            Self::GcpKms { .. } => "gcp-kms",
            Self::GoogleSecretManager { .. } => "gcp-sm",
            Self::Infisical { .. } => "infisical",
            Self::KeePass { .. } => "keepass",
            Self::Keychain { .. } => "keychain",
            Self::PasswordStore { .. } => "password-store",
            Self::Plain => "plain",
            Self::HashiCorpVault { .. } => "vault",
        }
    }
}
