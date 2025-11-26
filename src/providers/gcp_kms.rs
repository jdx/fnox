use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use google_cloud_kms::client::{Client, ClientConfig};
use google_cloud_kms::grpc::kms::v1::{DecryptRequest, EncryptRequest, GetCryptoKeyRequest};

pub struct GcpKmsProvider {
    project: String,
    location: String,
    keyring: String,
    key: String,
}

impl GcpKmsProvider {
    pub fn new(project: String, location: String, keyring: String, key: String) -> Self {
        Self {
            project,
            location,
            keyring,
            key,
        }
    }

    /// Get the full resource name for the crypto key
    fn key_name(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.project, self.location, self.keyring, self.key
        )
    }

    /// Create a GCP KMS client
    async fn create_client(&self) -> Result<Client> {
        let config = ClientConfig::default()
            .with_auth()
            .await
            .map_err(|e| FnoxError::Provider(format!("Failed to authenticate with GCP: {}", e)))?;

        Client::new(config)
            .await
            .map_err(|e| FnoxError::Provider(format!("Failed to create GCP KMS client: {}", e)))
    }

    /// Decrypt a ciphertext value using Cloud KMS
    async fn decrypt(&self, ciphertext_base64: &str) -> Result<String> {
        let client = self.create_client().await?;

        // Decode from base64
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_base64,
        )
        .map_err(|e| FnoxError::Provider(format!("Failed to decode base64 ciphertext: {}", e)))?;

        let request = DecryptRequest {
            name: self.key_name(),
            ciphertext: ciphertext_bytes,
            additional_authenticated_data: vec![],
            ..Default::default()
        };

        let response = client
            .decrypt(request, None)
            .await
            .map_err(|e| FnoxError::Provider(format!("Failed to decrypt with GCP KMS: {}", e)))?;

        // Convert bytes to string
        String::from_utf8(response.plaintext)
            .map_err(|e| FnoxError::Provider(format!("Decrypted value is not valid UTF-8: {}", e)))
    }
}

#[async_trait]
impl crate::providers::Provider for GcpKmsProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        // value contains the base64-encoded encrypted blob
        self.decrypt(value).await
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String> {
        let client = self.create_client().await?;

        let request = EncryptRequest {
            name: self.key_name(),
            plaintext: plaintext.as_bytes().to_vec(),
            additional_authenticated_data: vec![],
            ..Default::default()
        };

        let response = client
            .encrypt(request, None)
            .await
            .map_err(|e| FnoxError::Provider(format!("Failed to encrypt with GCP KMS: {}", e)))?;

        // Encode as base64 for storage
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            response.ciphertext,
        ))
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client().await?;

        // Try to get the key to verify access
        let request = GetCryptoKeyRequest {
            name: self.key_name(),
        };

        client.get_crypto_key(request, None).await.map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to connect to GCP KMS or access key '{}': {}",
                self.key_name(),
                e
            ))
        })?;

        Ok(())
    }
}
