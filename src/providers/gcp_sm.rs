use crate::error::{FnoxError, Result};
use crate::providers::{WizardCategory, WizardField, WizardInfo};
use async_trait::async_trait;
use google_cloud_secretmanager_v1::client::SecretManagerService;

pub const WIZARD_INFO: WizardInfo = WizardInfo {
    provider_type: "gcp-sm",
    display_name: "GCP Secret Manager",
    description: "Google Cloud Secret Manager",
    category: WizardCategory::CloudSecretsManager,
    setup_instructions: "\
Stores secrets in Google Cloud Secret Manager.
Requires GCP credentials configured.",
    default_name: "gcp-sm",
    fields: &[
        WizardField {
            name: "project",
            label: "GCP Project ID:",
            placeholder: "my-project",
            required: true,
        },
        WizardField {
            name: "prefix",
            label: "Secret name prefix (optional):",
            placeholder: "fnox-",
            required: false,
        },
    ],
};

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
            FnoxError::Provider(format!("Failed to create GCP Secret Manager client: {}", e))
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
        Err(FnoxError::Provider(
            "GCP Secret Manager put_secret not yet implemented. \
            Contributions welcome to implement payload data setting."
                .to_string(),
        ))
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
                FnoxError::Provider(format!(
                    "Failed to access secret '{}' from GCP Secret Manager: {}",
                    value, e
                ))
            })?;

        // Extract the payload data
        let payload = response
            .payload
            .ok_or_else(|| FnoxError::Provider("Secret has no payload".to_string()))?;

        // Convert bytes to string
        String::from_utf8(payload.data.to_vec())
            .map_err(|e| FnoxError::Provider(format!("Secret value is not valid UTF-8: {}", e)))
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
                FnoxError::Provider(format!(
                    "Failed to connect to GCP Secret Manager or access project '{}': {}",
                    self.project, e
                ))
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
