use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_keys::{
    KeyClient,
    models::{EncryptionAlgorithm, KeyOperationParameters},
};

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
        let credential = DeveloperToolsCredential::new(None).map_err(|e| {
            FnoxError::Provider(format!("Failed to create Azure credentials: {}", e))
        })?;

        KeyClient::new(&self.vault_url, credential, None).map_err(|e| {
            FnoxError::Provider(format!("Failed to create Azure Key Vault client: {}", e))
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
        .map_err(|e| FnoxError::Provider(format!("Failed to decode base64 ciphertext: {}", e)))?;

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
                params.try_into().map_err(|e| {
                    FnoxError::Provider(format!("Failed to create decrypt parameters: {}", e))
                })?,
                None,
            )
            .await
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to decrypt with Azure Key Vault: {}", e))
            })?;

        let result = response
            .into_model()
            .map_err(|e| FnoxError::Provider(format!("Failed to parse decrypt response: {}", e)))?;

        let plaintext_bytes = result
            .result
            .ok_or_else(|| FnoxError::Provider("Decrypt result has no value".to_string()))?;

        // Convert bytes to string
        String::from_utf8(plaintext_bytes)
            .map_err(|e| FnoxError::Provider(format!("Decrypted value is not valid UTF-8: {}", e)))
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
                params.try_into().map_err(|e| {
                    FnoxError::Provider(format!("Failed to create encrypt parameters: {}", e))
                })?,
                None,
            )
            .await
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to encrypt with Azure Key Vault: {}", e))
            })?;

        let result = response
            .into_model()
            .map_err(|e| FnoxError::Provider(format!("Failed to parse encrypt response: {}", e)))?;

        let ciphertext_bytes = result
            .result
            .ok_or_else(|| FnoxError::Provider("Encrypt result has no value".to_string()))?;

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
            FnoxError::Provider(format!(
                "Failed to connect to Azure Key Vault or access key '{}': {}",
                self.key_name, e
            ))
        })?;

        Ok(())
    }
}
