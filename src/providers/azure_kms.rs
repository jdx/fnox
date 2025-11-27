use crate::error::{FnoxError, Result};
use crate::providers::{WizardCategory, WizardField, WizardInfo};
use async_trait::async_trait;
use azure_core::auth::TokenCredential;
use azure_identity::{DefaultAzureCredential, TokenCredentialOptions};
use azure_security_keyvault::KeyClient;
use azure_security_keyvault::prelude::*;
use std::sync::Arc;

pub const WIZARD_INFO: WizardInfo = WizardInfo {
    provider_type: "azure-kms",
    display_name: "Azure Key Vault",
    description: "Azure Key Vault for encryption",
    category: WizardCategory::CloudKms,
    setup_instructions: "\
Encrypts secrets using Azure Key Vault keys.
Requires Azure credentials configured.",
    default_name: "azure-kms",
    fields: &[
        WizardField {
            name: "vault_url",
            label: "Key Vault URL:",
            placeholder: "https://my-vault.vault.azure.net/",
            required: true,
        },
        WizardField {
            name: "key_name",
            label: "Key name:",
            placeholder: "my-key",
            required: true,
        },
    ],
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
    async fn create_client(&self) -> Result<KeyClient> {
        // Use DefaultAzureCredential which supports multiple auth methods:
        // - Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
        // - Managed Identity
        // - Azure CLI
        let credential = DefaultAzureCredential::create(TokenCredentialOptions::default())
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to create Azure credentials: {}", e))
            })?;

        let credential = Arc::new(credential) as Arc<dyn TokenCredential>;

        KeyClient::new(&self.vault_url, credential).map_err(|e| {
            FnoxError::Provider(format!("Failed to create Azure Key Vault client: {}", e))
        })
    }

    /// Decrypt a ciphertext value using Azure Key Vault
    async fn decrypt(&self, ciphertext_base64: &str) -> Result<String> {
        let client = self.create_client().await?;

        // Decode from base64
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_base64,
        )
        .map_err(|e| FnoxError::Provider(format!("Failed to decode base64 ciphertext: {}", e)))?;

        // Create decrypt parameters with RSA-OAEP-256 algorithm
        let decrypt_params = DecryptParameters {
            ciphertext: ciphertext_bytes,
            decrypt_parameters_encryption: CryptographParamtersEncryption::Rsa(
                RsaEncryptionParameters {
                    algorithm: EncryptionAlgorithm::RsaOaep256,
                },
            ),
        };

        // Decrypt using Azure Key Vault
        let result = client
            .decrypt(&self.key_name, decrypt_params)
            .await
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to decrypt with Azure Key Vault: {}", e))
            })?;

        // Convert bytes to string
        String::from_utf8(result.result.to_vec())
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
        let client = self.create_client().await?;

        // Create encrypt parameters with RSA-OAEP-256 algorithm
        let encrypt_params = EncryptParameters {
            plaintext: plaintext.as_bytes().to_vec(),
            encrypt_parameters_encryption: CryptographParamtersEncryption::Rsa(
                RsaEncryptionParameters {
                    algorithm: EncryptionAlgorithm::RsaOaep256,
                },
            ),
        };

        // Encrypt using Azure Key Vault
        let result = client
            .encrypt(&self.key_name, encrypt_params)
            .await
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to encrypt with Azure Key Vault: {}", e))
            })?;

        // Encode as base64 for storage
        let ciphertext_bytes: &[u8] = result.result.as_ref();
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_bytes,
        ))
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client().await?;

        // Try to get the key to verify access
        client.get(&self.key_name).await.map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to connect to Azure Key Vault or access key '{}': {}",
                self.key_name, e
            ))
        })?;

        Ok(())
    }
}
