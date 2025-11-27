use crate::error::Result;
use async_trait::async_trait;
use std::collections::HashMap;

// Provider implementation modules
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

// Include generated code for ProviderConfig and ResolvedProviderConfig enums
mod generated {
    pub(super) mod providers_config {
        include!(concat!(env!("OUT_DIR"), "/generated/providers_config.rs"));
    }
    pub(super) mod providers_methods {
        include!(concat!(env!("OUT_DIR"), "/generated/providers_methods.rs"));
    }
    pub(super) mod providers_instantiate {
        // Need to import provider modules for instantiation
        use super::super::{
            age, aws_kms, aws_ps, aws_sm, azure_kms, azure_sm, bitwarden, gcp_kms, gcp_sm,
            infisical, keepass, keychain, onepassword, password_store, plain, vault,
        };
        include!(concat!(
            env!("OUT_DIR"),
            "/generated/providers_instantiate.rs"
        ));
    }
    pub(super) mod providers_wizard {
        include!(concat!(env!("OUT_DIR"), "/generated/providers_wizard.rs"));
    }
    pub(super) mod providers_resolver {
        include!(concat!(env!("OUT_DIR"), "/generated/providers_resolver.rs"));
    }
}

// Re-export generated types
pub use generated::providers_config::{ProviderConfig, ResolvedProviderConfig};
pub use generated::providers_instantiate::get_provider_from_resolved;
pub use generated::providers_wizard::ALL_WIZARD_INFO;

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
    /// Get wizard info for providers in a specific category
    pub fn wizard_info_by_category(category: WizardCategory) -> Vec<&'static WizardInfo> {
        ALL_WIZARD_INFO
            .iter()
            .filter(|info| info.category == category)
            .collect()
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
