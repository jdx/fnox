use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_keys::{
    KeyClient,
    models::{EncryptionAlgorithm, KeyOperationParameters},
};

const URL: &str = "https://fnox.jdx.dev/providers/azure-kms";

pub struct AzureKeyVaultProvider {
    vault_url: String,
    key_name: String,
}

impl AzureKeyVaultProvider {
    pub fn new(vault_url: String, key_name: String) -> Self {
        Self {
            vault_url,
            key_name,
        }
    }

    /// Create an Azure Key Vault key client
    fn create_client(&self) -> Result<KeyClient> {
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

        KeyClient::new(&self.vault_url, credential, None).map_err(|e| FnoxError::ProviderApiError {
            provider: "Azure Key Vault".to_string(),
            details: e.to_string(),
            hint: "Check your Azure Key Vault URL".to_string(),
            url: URL.to_string(),
        })
    }

    /// Decrypt a ciphertext value using Azure Key Vault
    async fn decrypt(&self, ciphertext_base64: &str) -> Result<String> {
        let client = self.create_client()?;

        // Decode from base64
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_base64,
        )
        .map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: "Azure Key Vault".to_string(),
            details: format!("Failed to decode base64 ciphertext: {}", e),
            hint: "The encrypted value appears to be corrupted".to_string(),
            url: URL.to_string(),
        })?;

        // Create decrypt parameters with RSA-OAEP-256 algorithm
        let params = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::RsaOaep256),
            value: Some(ciphertext_bytes),
            ..Default::default()
        };

        // Decrypt using Azure Key Vault
        let response = client
            .decrypt(
                &self.key_name,
                params
                    .try_into()
                    .map_err(|e| FnoxError::ProviderInvalidResponse {
                        provider: "Azure Key Vault".to_string(),
                        details: format!("Failed to create decrypt parameters: {}", e),
                        hint: "This is an unexpected error".to_string(),
                        url: URL.to_string(),
                    })?,
                None,
            )
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("KeyNotFound") || err_str.contains("not found") {
                    FnoxError::ProviderSecretNotFound {
                        provider: "Azure Key Vault".to_string(),
                        secret: self.key_name.clone(),
                        hint: "Check that the key exists in the vault".to_string(),
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

        let result = response
            .into_model()
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Azure Key Vault".to_string(),
                details: format!("Failed to parse decrypt response: {}", e),
                hint: "This is an unexpected error".to_string(),
                url: URL.to_string(),
            })?;

        let plaintext_bytes = result
            .result
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Azure Key Vault".to_string(),
                details: "Decrypt result has no value".to_string(),
                hint: "The decryption returned no plaintext".to_string(),
                url: URL.to_string(),
            })?;

        // Convert bytes to string
        String::from_utf8(plaintext_bytes).map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: "Azure Key Vault".to_string(),
            details: format!("Decrypted value is not valid UTF-8: {}", e),
            hint: "The decrypted value contains invalid UTF-8 characters".to_string(),
            url: URL.to_string(),
        })
    }
}

#[async_trait]
impl crate::providers::Provider for AzureKeyVaultProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        // value contains the base64-encoded encrypted blob
        self.decrypt(value).await
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String> {
        let client = self.create_client()?;

        // Create encrypt parameters with RSA-OAEP-256 algorithm
        let params = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::RsaOaep256),
            value: Some(plaintext.as_bytes().to_vec()),
            ..Default::default()
        };

        // Encrypt using Azure Key Vault
        let response = client
            .encrypt(
                &self.key_name,
                params
                    .try_into()
                    .map_err(|e| FnoxError::ProviderInvalidResponse {
                        provider: "Azure Key Vault".to_string(),
                        details: format!("Failed to create encrypt parameters: {}", e),
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

        let result = response
            .into_model()
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Azure Key Vault".to_string(),
                details: format!("Failed to parse encrypt response: {}", e),
                hint: "This is an unexpected error".to_string(),
                url: URL.to_string(),
            })?;

        let ciphertext_bytes = result
            .result
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Azure Key Vault".to_string(),
                details: "Encrypt result has no value".to_string(),
                hint: "The encryption returned no ciphertext".to_string(),
                url: URL.to_string(),
            })?;

        // Encode as base64 for storage
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ciphertext_bytes,
        ))
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client()?;

        // Try to get the key to verify access
        client.get_key(&self.key_name, None).await.map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("KeyNotFound") || err_str.contains("not found") {
                FnoxError::ProviderSecretNotFound {
                    provider: "Azure Key Vault".to_string(),
                    secret: self.key_name.clone(),
                    hint: "Check that the key exists in the vault".to_string(),
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
                    details: format!("Failed to access key '{}': {}", self.key_name, err_str),
                    hint: "Check your Azure Key Vault configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        })?;

        Ok(())
    }
}
