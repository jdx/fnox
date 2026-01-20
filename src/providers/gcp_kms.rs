use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use google_cloud_kms::client::{Client, ClientConfig};
use google_cloud_kms::grpc::kms::v1::{DecryptRequest, EncryptRequest, GetCryptoKeyRequest};

const URL: &str = "https://fnox.jdx.dev/providers/gcp-kms";

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
            .map_err(|e| FnoxError::ProviderAuthFailed {
                provider: "GCP KMS".to_string(),
                details: e.to_string(),
                hint: "Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                url: URL.to_string(),
            })?;

        Client::new(config)
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "GCP KMS".to_string(),
                details: e.to_string(),
                hint: "Check your GCP KMS configuration".to_string(),
                url: URL.to_string(),
            })
    }

    /// Decrypt a ciphertext value using Cloud KMS
    async fn decrypt(&self, ciphertext_base64: &str) -> Result<String> {
        let client = self.create_client().await?;

        // Decode from base64
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_base64,
        )
        .map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: "GCP KMS".to_string(),
            details: format!("Failed to decode base64 ciphertext: {}", e),
            hint: "The encrypted value appears to be corrupted".to_string(),
            url: URL.to_string(),
        })?;

        let request = DecryptRequest {
            name: self.key_name(),
            ciphertext: ciphertext_bytes,
            additional_authenticated_data: vec![],
            ..Default::default()
        };

        let response = client.decrypt(request, None).await.map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("PERMISSION_DENIED") || err_str.contains("permission") {
                FnoxError::ProviderAuthFailed {
                    provider: "GCP KMS".to_string(),
                    details: err_str,
                    hint: "Check IAM permissions for cloudkms.cryptoKeyVersions.useToDecrypt"
                        .to_string(),
                    url: URL.to_string(),
                }
            } else if err_str.contains("NOT_FOUND") || err_str.contains("not found") {
                FnoxError::ProviderSecretNotFound {
                    provider: "GCP KMS".to_string(),
                    secret: self.key_name(),
                    hint: "Check that the KMS key exists and is accessible".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "GCP KMS".to_string(),
                    details: err_str,
                    hint: "Check your GCP KMS configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        })?;

        // Convert bytes to string
        String::from_utf8(response.plaintext).map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: "GCP KMS".to_string(),
            details: format!("Decrypted value is not valid UTF-8: {}", e),
            hint: "The decrypted value contains invalid UTF-8 characters".to_string(),
            url: URL.to_string(),
        })
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

        let response = client.encrypt(request, None).await.map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("PERMISSION_DENIED") || err_str.contains("permission") {
                FnoxError::ProviderAuthFailed {
                    provider: "GCP KMS".to_string(),
                    details: err_str,
                    hint: "Check IAM permissions for cloudkms.cryptoKeyVersions.useToEncrypt"
                        .to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "GCP KMS".to_string(),
                    details: err_str,
                    hint: "Check your GCP KMS configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        })?;

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
            let err_str = e.to_string();
            if err_str.contains("NOT_FOUND") || err_str.contains("not found") {
                FnoxError::ProviderSecretNotFound {
                    provider: "GCP KMS".to_string(),
                    secret: self.key_name(),
                    hint: "Check that the KMS key exists".to_string(),
                    url: URL.to_string(),
                }
            } else if err_str.contains("PERMISSION_DENIED") || err_str.contains("permission") {
                FnoxError::ProviderAuthFailed {
                    provider: "GCP KMS".to_string(),
                    details: err_str,
                    hint: "Check IAM permissions for cloudkms.cryptoKeys.get".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "GCP KMS".to_string(),
                    details: err_str,
                    hint: "Check your GCP KMS configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        })?;

        Ok(())
    }
}
