use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client;
use aws_sdk_kms::primitives::Blob;

const URL: &str = "https://fnox.jdx.dev/providers/aws-kms";

/// Convert AWS SDK errors to structured FnoxError with appropriate hints
fn aws_kms_error_to_fnox<E, R>(
    err: &aws_sdk_kms::error::SdkError<E, R>,
    operation: &str,
    key_id: &str,
) -> FnoxError
where
    E: std::fmt::Debug + std::fmt::Display,
    R: std::fmt::Debug,
{
    use aws_sdk_kms::error::SdkError;

    match err {
        SdkError::ServiceError(service_err) => {
            let err_str = service_err.err().to_string();
            if err_str.contains("AccessDenied") || err_str.contains("UnauthorizedAccess") {
                FnoxError::ProviderAuthFailed {
                    provider: "AWS KMS".to_string(),
                    details: err_str,
                    hint: format!("Check IAM permissions for kms:{}", operation),
                    url: URL.to_string(),
                }
            } else if err_str.contains("NotFoundException") {
                FnoxError::ProviderSecretNotFound {
                    provider: "AWS KMS".to_string(),
                    secret: key_id.to_string(),
                    hint: "Check that the KMS key exists and is accessible".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "AWS KMS".to_string(),
                    details: err_str,
                    hint: "Check AWS KMS configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        }
        SdkError::TimeoutError(_) => FnoxError::ProviderApiError {
            provider: "AWS KMS".to_string(),
            details: "Request timed out".to_string(),
            hint: "Check network connectivity and AWS region endpoint".to_string(),
            url: URL.to_string(),
        },
        SdkError::DispatchFailure(dispatch_err) => {
            if let Some(connector_err) = dispatch_err.as_connector_error() {
                let mut error_chain = vec![connector_err.to_string()];
                let mut source = std::error::Error::source(connector_err);
                while let Some(err) = source {
                    error_chain.push(err.to_string());
                    source = std::error::Error::source(err);
                }
                let full_error = error_chain.join(": ");

                let hint = if full_error.contains("dns error")
                    || full_error.contains("failed to lookup address")
                {
                    "DNS resolution failed - check network and AWS region"
                } else if full_error.contains("connection refused") {
                    "Connection refused - check AWS endpoint accessibility"
                } else if full_error.contains("tls")
                    || full_error.contains("ssl")
                    || full_error.contains("certificate")
                {
                    "TLS/SSL error - check certificates or proxy config"
                } else if full_error.contains("timeout") {
                    "Connection timeout - check network and firewall"
                } else if full_error.contains("No credentials")
                    || full_error.contains("Unable to load credentials")
                {
                    "Run 'aws sso login' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY"
                } else {
                    "Check network connectivity"
                };

                if full_error.contains("credentials") {
                    FnoxError::ProviderAuthFailed {
                        provider: "AWS KMS".to_string(),
                        details: full_error,
                        hint: hint.to_string(),
                        url: URL.to_string(),
                    }
                } else {
                    FnoxError::ProviderApiError {
                        provider: "AWS KMS".to_string(),
                        details: full_error,
                        hint: hint.to_string(),
                        url: URL.to_string(),
                    }
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "AWS KMS".to_string(),
                    details: format!("{:?}", dispatch_err),
                    hint: "Check network connectivity".to_string(),
                    url: URL.to_string(),
                }
            }
        }
        _ => FnoxError::ProviderApiError {
            provider: "AWS KMS".to_string(),
            details: err.to_string(),
            hint: "Check AWS configuration".to_string(),
            url: URL.to_string(),
        },
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
        .map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: "AWS KMS".to_string(),
            details: format!("Failed to decode base64 ciphertext: {}", e),
            hint: "The encrypted value appears to be corrupted".to_string(),
            url: URL.to_string(),
        })?;

        let result = client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(Blob::new(ciphertext_bytes))
            .send()
            .await
            .map_err(|e| aws_kms_error_to_fnox(&e, "Decrypt", &self.key_id))?;

        let plaintext_blob =
            result
                .plaintext()
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: "AWS KMS".to_string(),
                    details: "Decrypt returned no plaintext".to_string(),
                    hint: "The KMS key may not be able to decrypt this ciphertext".to_string(),
                    url: URL.to_string(),
                })?;

        // Convert bytes to string
        String::from_utf8(plaintext_blob.as_ref().to_vec()).map_err(|e| {
            FnoxError::ProviderInvalidResponse {
                provider: "AWS KMS".to_string(),
                details: format!("Decrypted value is not valid UTF-8: {}", e),
                hint: "The decrypted value contains invalid UTF-8 characters".to_string(),
                url: URL.to_string(),
            }
        })
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
            .map_err(|e| aws_kms_error_to_fnox(&e, "Encrypt", &self.key_id))?;

        let ciphertext_blob =
            result
                .ciphertext_blob()
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: "AWS KMS".to_string(),
                    details: "Encrypt returned no ciphertext".to_string(),
                    hint: "This is an unexpected error".to_string(),
                    url: URL.to_string(),
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
            .map_err(|e| aws_kms_error_to_fnox(&e, "DescribeKey", &self.key_id))?;

        Ok(())
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> std::collections::HashMap<String, Result<String>> {
        // AWS KMS has a rate limit allowance of 10000+ TPS by default.
        // 10 -> 100 should generally not cause issues.
        crate::providers::get_secrets_concurrent(self, secrets, 100).await
    }
}
