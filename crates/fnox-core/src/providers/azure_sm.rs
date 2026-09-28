use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_core::{Error, error::ErrorKind, http::StatusCode};
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters};

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

const URL: &str = "https://fnox.jdx.dev/providers/azure-sm";
const CONNECTION_TEST_SECRET: &str = "fnox-test-secret";

fn handle_connection_test_error(vault_url: &str, error: Error) -> Result<()> {
    let details = error.to_string();

    match error.kind() {
        ErrorKind::HttpResponse {
            status: StatusCode::NotFound,
            error_code: Some(error_code),
            ..
        } if error_code == "SecretNotFound" => Ok(()),
        ErrorKind::HttpResponse {
            status: StatusCode::Unauthorized | StatusCode::Forbidden,
            ..
        } => Err(FnoxError::ProviderAuthFailed {
            provider: "Azure Key Vault".to_string(),
            details,
            hint: "Check your Azure Key Vault access policies".to_string(),
            url: URL.to_string(),
        }),
        _ => Err(FnoxError::ProviderApiError {
            provider: "Azure Key Vault".to_string(),
            details: format!("Failed to connect to vault '{}': {}", vault_url, details),
            hint: "Check your Azure Key Vault URL and network connectivity".to_string(),
            url: URL.to_string(),
        }),
    }
}

pub struct AzureSecretsManagerProvider {
    vault_url: String,
    prefix: Option<String>,
}

impl AzureSecretsManagerProvider {
    pub fn new(vault_url: String, prefix: Option<String>) -> Result<Self> {
        Ok(Self { vault_url, prefix })
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

        // Probe the read path without requiring list or write permissions
        // A missing connection-test secret still confirms authenticated vault access
        match client.get_secret(CONNECTION_TEST_SECRET, None).await {
            Ok(_) => Ok(()),
            Err(error) => handle_connection_test_error(&self.vault_url, error),
        }
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let secret_name = self.get_secret_name(key);
        self.put_secret(&secret_name, value).await?;
        // Return the key name (without prefix) to store in config
        Ok(key.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_error(status: StatusCode, error_code: &str) -> Error {
        Error::with_message(
            ErrorKind::HttpResponse {
                status,
                error_code: Some(error_code.to_string()),
                raw_response: None,
            },
            error_code.to_string(),
        )
    }

    #[test]
    fn missing_test_secret_confirms_connection() {
        let error = http_error(StatusCode::NotFound, "SecretNotFound");

        assert!(handle_connection_test_error("https://example.vault.azure.net/", error).is_ok());
    }

    #[test]
    fn missing_vault_reports_api_error() {
        let error = http_error(StatusCode::NotFound, "VaultNotFound");
        let result = handle_connection_test_error("https://missing.vault.azure.net/", error);

        assert!(matches!(result, Err(FnoxError::ProviderApiError { .. })));
    }

    #[test]
    fn forbidden_test_secret_reports_auth_failure() {
        let error = http_error(StatusCode::Forbidden, "Forbidden");
        let result = handle_connection_test_error("https://example.vault.azure.net/", error);

        assert!(matches!(result, Err(FnoxError::ProviderAuthFailed { .. })));
    }

    #[test]
    fn connection_failure_reports_api_error() {
        let error = Error::with_message(ErrorKind::Connection, "connection refused");
        let result = handle_connection_test_error("https://example.vault.azure.net/", error);

        assert!(matches!(result, Err(FnoxError::ProviderApiError { .. })));
    }
}
