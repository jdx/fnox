use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_identity::{ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential};
use azure_security_keyvault_keys::{
    KeyClient,
    models::{EncryptionAlgorithm, KeyOperationParameters},
};
use std::sync::Arc;

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

    /// Create an Azure Key Vault key client
    fn create_client(&self) -> Result<KeyClient> {
        let credential = Self::create_credential()?;

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
