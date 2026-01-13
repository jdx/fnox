use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client;
use aws_sdk_kms::primitives::Blob;

/// Helper function to extract detailed error information from AWS SDK errors
fn format_aws_error<E, R>(err: &aws_sdk_kms::error::SdkError<E, R>) -> String
where
    E: std::fmt::Debug + std::fmt::Display,
    R: std::fmt::Debug,
{
    use aws_sdk_kms::error::SdkError;

    match err {
        SdkError::ServiceError(service_err) => {
            // Extract service-specific error details
            format!("{}", service_err.err())
        }
        SdkError::TimeoutError(timeout_err) => {
            format!("Request timed out: {:?}", timeout_err)
        }
        SdkError::DispatchFailure(dispatch_err) => {
            // Unwrap dispatch failure to show underlying cause
            if let Some(source) = dispatch_err.as_connector_error() {
                format!("Network error: {}", source)
            } else {
                format!("Dispatch failure: {:?}", dispatch_err)
            }
        }
        SdkError::ConstructionFailure(construction_err) => {
            format!("Request construction failed: {:?}", construction_err)
        }
        SdkError::ResponseError(response_err) => {
            format!("Response error: {:?}", response_err)
        }
        _ => format!("{}", err),
    }
}

pub struct AwsKmsProvider {
    key_id: String,
    region: String,
}

impl AwsKmsProvider {
    pub fn new(key_id: String, region: String) -> Self {
        Self { key_id, region }
    }

    /// Create an AWS KMS client
    async fn create_client(&self) -> Result<Client> {
        // Load AWS config with the specified region
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_kms::config::Region::new(self.region.clone()))
            .load()
            .await;

        Ok(Client::new(&config))
    }

    /// Decrypt a ciphertext value using KMS
    async fn decrypt(&self, ciphertext_base64: &str) -> Result<String> {
        let client = self.create_client().await?;

        // Decode from base64
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_base64,
        )
        .map_err(|e| FnoxError::Provider(format!("Failed to decode base64 ciphertext: {}", e)))?;

        let result = client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(Blob::new(ciphertext_bytes))
            .send()
            .await
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to decrypt with AWS KMS: {}", format_aws_error(&e)))
            })?;

        let plaintext_blob = result.plaintext().ok_or_else(|| {
            FnoxError::Provider("AWS KMS decrypt returned no plaintext".to_string())
        })?;

        // Convert bytes to string
        String::from_utf8(plaintext_blob.as_ref().to_vec())
            .map_err(|e| FnoxError::Provider(format!("Decrypted value is not valid UTF-8: {}", e)))
    }
}

#[async_trait]
impl crate::providers::Provider for AwsKmsProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        // value contains the base64-encoded encrypted blob
        self.decrypt(value).await
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String> {
        let client = self.create_client().await?;

        let result = client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(plaintext.as_bytes()))
            .send()
            .await
            .map_err(|e| {
                FnoxError::Provider(format!("Failed to encrypt with AWS KMS: {}", format_aws_error(&e)))
            })?;

        let ciphertext_blob = result.ciphertext_blob().ok_or_else(|| {
            FnoxError::Provider("AWS KMS encrypt returned no ciphertext".to_string())
        })?;

        // Encode as base64 for storage
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_blob.as_ref(),
        ))
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client().await?;

        // Try to describe the key to verify access
        client
            .describe_key()
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to connect to AWS KMS or access key '{}': {}",
                    self.key_id,
                    format_aws_error(&e)
                ))
            })?;

        Ok(())
    }
}
