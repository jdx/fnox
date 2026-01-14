use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_identity::{ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential};
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters};
use std::sync::Arc;

pub struct AzureSecretsManagerProvider {
    vault_url: String,
    prefix: Option<String>,
}

impl AzureSecretsManagerProvider {
    pub fn new(vault_url: String, prefix: Option<String>) -> Self {
        Self { vault_url, prefix }
    }

    pub fn get_secret_name(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}{}", prefix, key),
            None => key.to_string(),
        }
    }

    /// Create an Azure credential that supports multiple authentication methods.
    ///
    /// Tries credentials in this order:
    /// 1. ClientSecretCredential - if AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET are set
    /// 2. ManagedIdentityCredential - for Azure-hosted environments (VMs, App Service, etc.)
    /// 3. DeveloperToolsCredential - Azure CLI and Azure Developer CLI for local development
    fn create_credential() -> Result<Arc<dyn TokenCredential>> {
        // Try service principal authentication first (for CI/CD and production)
        if let (Ok(tenant_id), Ok(client_id), Ok(client_secret)) = (
            std::env::var("AZURE_TENANT_ID"),
            std::env::var("AZURE_CLIENT_ID"),
            std::env::var("AZURE_CLIENT_SECRET"),
        ) {
            tracing::debug!("Using ClientSecretCredential for Azure authentication");
            return ClientSecretCredential::new(
                &tenant_id,
                client_id,
                azure_core::credentials::Secret::new(client_secret),
                None,
            )
            .map(|c| c as Arc<dyn TokenCredential>)
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to create ClientSecretCredential: {}", e))
            });
        }

        // Try managed identity (for Azure-hosted environments)
        if let Ok(credential) = ManagedIdentityCredential::new(None) {
            tracing::debug!("Using ManagedIdentityCredential for Azure authentication");
            return Ok(credential as Arc<dyn TokenCredential>);
        }

        // Fall back to developer tools (Azure CLI, Azure Developer CLI)
        tracing::debug!("Using DeveloperToolsCredential for Azure authentication");
        DeveloperToolsCredential::new(None)
            .map(|c| c as Arc<dyn TokenCredential>)
            .map_err(|e| FnoxError::Provider(format!("Failed to create Azure credentials: {}", e)))
    }

    /// Create an Azure Key Vault secret client
    fn create_client(&self) -> Result<SecretClient> {
        let credential = Self::create_credential()?;

        SecretClient::new(&self.vault_url, credential, None).map_err(|e| {
            FnoxError::Provider(format!("Failed to create Azure Key Vault client: {}", e))
        })
    }

    /// Get a secret value from Azure Key Vault
    async fn get_secret_value(&self, secret_name: &str) -> Result<String> {
        let client = self.create_client()?;

        let response = client.get_secret(secret_name, None).await.map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to get secret '{}' from Azure Key Vault: {}",
                secret_name, e
            ))
        })?;

        let secret = response
            .into_model()
            .map_err(|e| FnoxError::Provider(format!("Failed to parse secret response: {}", e)))?;

        secret
            .value
            .ok_or_else(|| FnoxError::Provider(format!("Secret '{}' has no value", secret_name)))
    }

    /// Create or update a secret in Azure Key Vault
    pub async fn put_secret(&self, secret_name: &str, secret_value: &str) -> Result<()> {
        let client = self.create_client()?;

        let params = SetSecretParameters {
            value: Some(secret_value.to_string()),
            ..Default::default()
        };

        // Azure Key Vault uses set to both create and update secrets
        client
            .set_secret(
                secret_name,
                params.try_into().map_err(|e| {
                    FnoxError::Provider(format!("Failed to create set_secret parameters: {}", e))
                })?,
                None,
            )
            .await
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to set secret '{}' in Azure Key Vault: {}",
                    secret_name, e
                ))
            })?;

        tracing::debug!("Set secret '{}' in Azure Key Vault", secret_name);
        Ok(())
    }
}

#[async_trait]
impl crate::providers::Provider for AzureSecretsManagerProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let secret_name = self.get_secret_name(value);
        tracing::debug!(
            "Getting secret '{}' from Azure Key Vault '{}'",
            secret_name,
            self.vault_url
        );

        self.get_secret_value(&secret_name).await
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client()?;

        // Try to get a secret to verify connection
        // We'll try to get the fnox-test-secret we created earlier
        client
            .get_secret("fnox-test-secret", None)
            .await
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to connect to Azure Key Vault '{}': {}",
                    self.vault_url, e
                ))
            })?;

        Ok(())
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let secret_name = self.get_secret_name(key);
        self.put_secret(&secret_name, value).await?;
        // Return the key name (without prefix) to store in config
        Ok(key.to_string())
    }
}
