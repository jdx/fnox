use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use google_cloud_kms_v1::client::KeyManagementService;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

const URL: &str = "https://fnox.jdx.dev/providers/gcp-kms";

const PROVIDER_NAME: &str = "GCP KMS";

pub struct GcpKmsProvider {
    project: String,
    location: String,
    keyring: String,
    key: String,
}

impl GcpKmsProvider {
    pub fn new(project: String, location: String, keyring: String, key: String) -> Result<Self> {
        Ok(Self {
            project,
            location,
            keyring,
            key,
        })
    }

    /// Get the full resource name for the crypto key
    fn key_name(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.project, self.location, self.keyring, self.key
        )
    }

    /// Create a GCP KMS client.
    ///
    /// The client uses the HTTP transport, which honors the standard
    /// `HTTPS_PROXY`/`https_proxy`/`NO_PROXY` environment variables.
    async fn create_client(&self) -> Result<KeyManagementService> {
        KeyManagementService::builder().build().await.map_err(|e| {
            let details = e.to_string();
            if details.contains("credentials")
                || details.contains("authentication")
                || details.contains("GOOGLE_APPLICATION_CREDENTIALS")
            {
                FnoxError::ProviderAuthFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details,
                    hint: "Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: PROVIDER_NAME.to_string(),
                    details,
                    hint: "Check your GCP KMS configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        })
    }

    /// Map a KMS API error to a fnox error.
    ///
    /// `permission` names the IAM permission the call needs; `not_found_hint`
    /// is used when the key does not exist (`None` treats it as an API error).
    fn convert_error(
        &self,
        e: google_cloud_kms_v1::Error,
        permission: &str,
        not_found_hint: Option<&str>,
    ) -> FnoxError {
        let details = e.to_string();
        // Credential failures (e.g. a revoked ADC refresh token) happen before
        // the RPC is sent, so they carry no status code.
        if e.is_authentication() {
            return FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details,
                hint: "Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                url: URL.to_string(),
            };
        }
        let code = e.status().map(|s| s.code.name());
        match (code, not_found_hint) {
            (Some("PERMISSION_DENIED" | "UNAUTHENTICATED"), _) => FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details,
                hint: format!("Check IAM permissions for {permission}"),
                url: URL.to_string(),
            },
            (Some("NOT_FOUND"), Some(hint)) => FnoxError::ProviderSecretNotFound {
                provider: PROVIDER_NAME.to_string(),
                secret: self.key_name(),
                hint: hint.to_string(),
                url: URL.to_string(),
            },
            _ => FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details,
                hint: "Check your GCP KMS configuration".to_string(),
                url: URL.to_string(),
            },
        }
    }

    /// Decrypt a ciphertext value using Cloud KMS
    async fn decrypt(&self, ciphertext_base64: &str) -> Result<String> {
        // Decode from base64 before contacting KMS
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_base64,
        )
        .map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: PROVIDER_NAME.to_string(),
            details: format!("Failed to decode base64 ciphertext: {}", e),
            hint: "The encrypted value appears to be corrupted".to_string(),
            url: URL.to_string(),
        })?;

        let client = self.create_client().await?;
        let response = client
            .decrypt()
            .set_name(self.key_name())
            .set_ciphertext(ciphertext_bytes)
            .send()
            .await
            .map_err(|e| {
                self.convert_error(
                    e,
                    "cloudkms.cryptoKeyVersions.useToDecrypt",
                    Some("Check that the KMS key exists and is accessible"),
                )
            })?;

        // Convert bytes to string
        String::from_utf8(response.plaintext.to_vec()).map_err(|e| {
            FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Decrypted value is not valid UTF-8: {}", e),
                hint: "The decrypted value contains invalid UTF-8 characters".to_string(),
                url: URL.to_string(),
            }
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

        let response = client
            .encrypt()
            .set_name(self.key_name())
            .set_plaintext(plaintext.as_bytes().to_vec())
            .send()
            .await
            .map_err(|e| self.convert_error(e, "cloudkms.cryptoKeyVersions.useToEncrypt", None))?;

        // Encode as base64 for storage
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            response.ciphertext,
        ))
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client().await?;

        // Try to get the key to verify access
        client
            .get_crypto_key()
            .set_name(self.key_name())
            .send()
            .await
            .map_err(|e| {
                self.convert_error(
                    e,
                    "cloudkms.cryptoKeys.get",
                    Some("Check that the KMS key exists"),
                )
            })?;

        Ok(())
    }
}
