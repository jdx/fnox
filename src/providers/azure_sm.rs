use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters};

const URL: &str = "https://fnox.jdx.dev/providers/azure-sm";

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
        let credential =
            DeveloperToolsCredential::new(None).map_err(|e| FnoxError::ProviderAuthFailed {
                provider: "Azure Key Vault".to_string(),
                details: e.to_string(),
                hint: "Run 'az login' to authenticate with Azure".to_string(),
                url: URL.to_string(),
            })?;

        SecretClient::new(&self.vault_url, credential, None).map_err(|e| {
            FnoxError::ProviderApiError {
                provider: "Azure Key Vault".to_string(),
                details: e.to_string(),
                hint: "Check your Azure Key Vault URL".to_string(),
                url: URL.to_string(),
            }
        })
    }

    /// Get a secret value from Azure Key Vault
    async fn get_secret_value(&self, secret_name: &str) -> Result<String> {
        let client = self.create_client()?;

        let response = client.get_secret(secret_name, None).await.map_err(|e| {
            let err_str = e.to_string();
            // Check for Azure-specific "not found" error patterns
            if err_str.contains("SecretNotFound")
                || err_str.contains("ResourceNotFound")
                || err_str.contains("Secret not found")
                || err_str.contains("was not found in this key vault")
            {
                FnoxError::ProviderSecretNotFound {
                    provider: "Azure Key Vault".to_string(),
                    secret: secret_name.to_string(),
                    hint: "Check that the secret exists in the vault".to_string(),
                    url: URL.to_string(),
                }
            } else if err_str.contains("Forbidden") || err_str.contains("Unauthorized") {
                FnoxError::ProviderAuthFailed {
                    provider: "Azure Key Vault".to_string(),
                    details: err_str,
                    hint: "Check your Azure Key Vault access policies".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "Azure Key Vault".to_string(),
                    details: err_str,
                    hint: "Check your Azure Key Vault configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        })?;

        let secret = response
            .into_model()
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Azure Key Vault".to_string(),
                details: format!("Failed to parse secret response: {}", e),
                hint: "This is an unexpected error".to_string(),
                url: URL.to_string(),
            })?;

        secret
            .value
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Azure Key Vault".to_string(),
                details: format!("Secret '{}' has no value", secret_name),
                hint: "The secret exists but has no value set".to_string(),
                url: URL.to_string(),
            })
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
                params
                    .try_into()
                    .map_err(|e| FnoxError::ProviderInvalidResponse {
                        provider: "Azure Key Vault".to_string(),
                        details: format!("Failed to create set_secret parameters: {}", e),
                        hint: "This is an unexpected error".to_string(),
                        url: URL.to_string(),
                    })?,
                None,
            )
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("Forbidden") || err_str.contains("Unauthorized") {
                    FnoxError::ProviderAuthFailed {
                        provider: "Azure Key Vault".to_string(),
                        details: err_str,
                        hint: "Check your Azure Key Vault access policies".to_string(),
                        url: URL.to_string(),
                    }
                } else {
                    FnoxError::ProviderApiError {
                        provider: "Azure Key Vault".to_string(),
                        details: err_str,
                        hint: "Check your Azure Key Vault configuration".to_string(),
                        url: URL.to_string(),
                    }
                }
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
                let err_str = e.to_string();
                if err_str.contains("Forbidden") || err_str.contains("Unauthorized") {
                    FnoxError::ProviderAuthFailed {
                        provider: "Azure Key Vault".to_string(),
                        details: err_str,
                        hint: "Check your Azure Key Vault access policies".to_string(),
                        url: URL.to_string(),
                    }
                } else {
                    FnoxError::ProviderApiError {
                        provider: "Azure Key Vault".to_string(),
                        details: format!(
                            "Failed to connect to vault '{}': {}",
                            self.vault_url, err_str
                        ),
                        hint: "Check your Azure Key Vault URL and network connectivity".to_string(),
                        url: URL.to_string(),
                    }
                }
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
