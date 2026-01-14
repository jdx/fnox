use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters};

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
    fn create_client(&self) -> Result<SecretClient> {
        // Use DeveloperToolsCredential which supports multiple auth methods:
        // - Azure CLI
        // - Azure Developer CLI
        let credential = DeveloperToolsCredential::new(None).map_err(|e| {
            FnoxError::Provider(format!("Failed to create Azure credentials: {}", e))
        })?;

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
