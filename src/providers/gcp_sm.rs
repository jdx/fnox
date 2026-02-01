use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use google_cloud_secretmanager_v1::client::SecretManagerService;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

const URL: &str = "https://fnox.jdx.dev/providers/gcp-sm";

pub struct GoogleSecretManagerProvider {
    project: String,
    prefix: Option<String>,
}

impl GoogleSecretManagerProvider {
    pub fn new(project: String, prefix: Option<String>) -> Self {
        Self { project, prefix }
    }

    /// Build the full secret name with optional prefix
    fn build_secret_name(&self, value: &str) -> String {
        let secret_name = if let Some(prefix) = &self.prefix {
            format!("{}{}", prefix, value)
        } else {
            value.to_string()
        };

        format!(
            "projects/{}/secrets/{}/versions/latest",
            self.project, secret_name
        )
    }

    /// Create a Secret Manager client
    async fn create_client(&self) -> Result<SecretManagerService> {
        SecretManagerService::builder().build().await.map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("credentials")
                || err_str.contains("authentication")
                || err_str.contains("GOOGLE_APPLICATION_CREDENTIALS")
            {
                FnoxError::ProviderAuthFailed {
                    provider: "GCP Secret Manager".to_string(),
                    details: err_str,
                    hint: "Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "GCP Secret Manager".to_string(),
                    details: err_str,
                    hint: "Check your GCP project configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        })
    }

    /// Get the secret ID (without version path)
    fn get_secret_id(&self, key: &str) -> String {
        if let Some(prefix) = &self.prefix {
            format!("{}{}", prefix, key)
        } else {
            key.to_string()
        }
    }

    /// Create or update a secret in GCP Secret Manager
    /// Note: This is a placeholder - full implementation requires determining
    /// the correct API for setting payload data in google-cloud-secretmanager-v1 crate
    async fn put_secret_value(&self, _secret_id: &str, _secret_value: &str) -> Result<()> {
        Err(FnoxError::ProviderApiError {
            provider: "GCP Secret Manager".to_string(),
            details: "put_secret not yet implemented".to_string(),
            hint: "Contributions welcome to implement payload data setting".to_string(),
            url: URL.to_string(),
        })
    }
}

#[async_trait]
impl crate::providers::Provider for GoogleSecretManagerProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let client = self.create_client().await?;
        let secret_name = self.build_secret_name(value);

        let response = client
            .access_secret_version()
            .set_name(secret_name)
            .send()
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("NOT_FOUND") || err_str.contains("not found") {
                    FnoxError::ProviderSecretNotFound {
                        provider: "GCP Secret Manager".to_string(),
                        secret: value.to_string(),
                        hint: "Check that the secret exists in the GCP project".to_string(),
                        url: URL.to_string(),
                    }
                } else if err_str.contains("PERMISSION_DENIED") || err_str.contains("permission") {
                    FnoxError::ProviderAuthFailed {
                        provider: "GCP Secret Manager".to_string(),
                        details: err_str,
                        hint: "Check IAM permissions for secretmanager.versions.access".to_string(),
                        url: URL.to_string(),
                    }
                } else {
                    FnoxError::ProviderApiError {
                        provider: "GCP Secret Manager".to_string(),
                        details: err_str,
                        hint: "Check your GCP configuration".to_string(),
                        url: URL.to_string(),
                    }
                }
            })?;

        // Extract the payload data
        let payload = response
            .payload
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "GCP Secret Manager".to_string(),
                details: "Secret has no payload".to_string(),
                hint: "The secret exists but has no value".to_string(),
                url: URL.to_string(),
            })?;

        // Convert bytes to string
        String::from_utf8(payload.data.to_vec()).map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: "GCP Secret Manager".to_string(),
            details: format!("Secret value is not valid UTF-8: {}", e),
            hint: "The secret contains binary data that cannot be decoded as UTF-8".to_string(),
            url: URL.to_string(),
        })
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client().await?;

        // Try to list secrets to verify access
        client
            .list_secrets()
            .set_parent(format!("projects/{}", self.project))
            .send()
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("PERMISSION_DENIED") || err_str.contains("permission") {
                    FnoxError::ProviderAuthFailed {
                        provider: "GCP Secret Manager".to_string(),
                        details: err_str,
                        hint: "Check IAM permissions for secretmanager.secrets.list".to_string(),
                        url: URL.to_string(),
                    }
                } else {
                    FnoxError::ProviderApiError {
                        provider: "GCP Secret Manager".to_string(),
                        details: format!(
                            "Failed to access project '{}': {}",
                            self.project, err_str
                        ),
                        hint: "Check that the project exists and you have access".to_string(),
                        url: URL.to_string(),
                    }
                }
            })?;

        Ok(())
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let secret_id = self.get_secret_id(key);
        self.put_secret_value(&secret_id, value).await?;
        // Return the key name (without prefix) to store in config
        Ok(key.to_string())
    }
}
