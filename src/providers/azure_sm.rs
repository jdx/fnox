use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_core::auth::TokenCredential;
use azure_identity::{DefaultAzureCredential, TokenCredentialOptions};
use azure_security_keyvault::SecretClient;
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

    /// Create an Azure Key Vault secret client
    async fn create_client(&self) -> Result<SecretClient> {
        // Use DefaultAzureCredential which supports multiple auth methods:
        // - Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
        // - Managed Identity
        // - Azure CLI
        let credential = DefaultAzureCredential::create(TokenCredentialOptions::default())
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to create Azure credentials: {}", e))
            })?;

        let credential = Arc::new(credential) as Arc<dyn TokenCredential>;

        SecretClient::new(&self.vault_url, credential).map_err(|e| {
            FnoxError::Provider(format!("Failed to create Azure Key Vault client: {}", e))
        })
    }

    /// Get a secret value from Azure Key Vault
    async fn get_secret_value(&self, secret_name: &str) -> Result<String> {
        let client = self.create_client().await?;

        let result = client.get(secret_name).await.map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to get secret '{}' from Azure Key Vault: {}",
                secret_name, e
            ))
        })?;

        Ok(result.value)
    }

    /// Create or update a secret in Azure Key Vault
    pub async fn put_secret(&self, secret_name: &str, secret_value: &str) -> Result<()> {
        let client = self.create_client().await?;

        // Azure Key Vault uses set to both create and update secrets
        client.set(secret_name, secret_value).await.map_err(|e| {
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
        let client = self.create_client().await?;

        // Try to get a secret to verify connection
        // We'll try to get the fnox-test-secret we created earlier
        client.get("fnox-test-secret").await.map_err(|e| {
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
