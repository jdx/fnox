use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use google_cloud_secretmanager_v1::{
    client::SecretManagerService,
    model::{Replication, Secret, SecretPayload, replication::Automatic},
};

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

const URL: &str = "https://fnox.jdx.dev/providers/gcp-sm";

const PROVIDER_NAME: &str = "GCP Secret Manager";

pub struct GoogleSecretManagerProvider {
    project: String,
    prefix: Option<String>,
}

impl GoogleSecretManagerProvider {
    pub fn new(project: String, prefix: Option<String>) -> Result<Self> {
        Ok(Self { project, prefix })
    }

    /// Build the full secret name with optional prefix
    fn build_secret_name(&self, value: &str) -> String {
        format!(
            "projects/{}/secrets/{}/versions/latest",
            self.project,
            self.get_secret_id(value)
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
                    provider: PROVIDER_NAME.to_string(),
                    details: err_str,
                    hint: "Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: PROVIDER_NAME.to_string(),
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
    async fn put_secret_value(&self, secret_id: &str, secret_value: &str) -> Result<()> {
        let client = self.create_client().await?;

        let project = self.project.as_str();
        let parent = format!("projects/{project}");
        let name = format!("{parent}/secrets/{secret_id}");

        match add_secret_version(&client, &name, secret_value).await {
            Ok(_) => Ok(()),
            Err(e) if e.http_status_code() == Some(404) => {
                if let Err(e) = create_secret(&client, &parent, secret_id, &name).await
                    && e.http_status_code() != Some(409)
                {
                    return Err(convert_provider_error(e, "secretmanager.secrets.create"));
                }

                add_secret_version(&client, &name, secret_value)
                    .await
                    .map_err(|e| convert_provider_error(e, "secretmanager.versions.add"))
            }
            Err(e) => Err(convert_provider_error(e, "secretmanager.versions.add")),
        }
    }
}

async fn create_secret(
    client: &SecretManagerService,
    parent: &str,
    secret_id: &str,
    name: &str,
) -> google_cloud_secretmanager_v1::Result<()> {
    client
        .create_secret()
        .set_parent(parent)
        .set_secret_id(secret_id)
        .set_secret(
            Secret::new()
                .set_name(name)
                .set_replication(Replication::new().set_automatic(Automatic::new())),
        )
        .send()
        .await?;

    Ok(())
}

async fn add_secret_version(
    client: &SecretManagerService,
    qualified_secret_name: &str,
    secret_value: &str,
) -> google_cloud_secretmanager_v1::Result<()> {
    client
        .add_secret_version()
        .set_parent(qualified_secret_name)
        .set_payload(SecretPayload::new().set_data(Bytes::copy_from_slice(secret_value.as_bytes())))
        .send()
        .await?;

    Ok(())
}

fn convert_secret_error(
    e: google_cloud_secretmanager_v1::Error,
    secret_id: &str,
    permission: &str,
) -> FnoxError {
    let err_str = e.to_string();

    if err_str.contains("NOT_FOUND") || err_str.contains("not found") {
        FnoxError::ProviderSecretNotFound {
            provider: PROVIDER_NAME.to_string(),
            secret: secret_id.to_string(),
            hint: "Check that the secret exists in the GCP project".to_string(),
            url: URL.to_string(),
        }
    } else {
        convert_provider_error(e, permission)
    }
}

fn convert_provider_error(e: google_cloud_secretmanager_v1::Error, permission: &str) -> FnoxError {
    let err_str = e.to_string();

    if err_str.contains("PERMISSION_DENIED") || err_str.contains("permission") {
        FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details: err_str,
            hint: format!("Check IAM permissions for {permission}"),
            url: URL.to_string(),
        }
    } else {
        FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details: err_str,
            hint: "Check your GCP configuration".to_string(),
            url: URL.to_string(),
        }
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
            .map_err(|e| convert_secret_error(e, value, "secretmanager.versions.access"))?;

        // Extract the payload data
        let payload = response
            .payload
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: "Secret has no payload".to_string(),
                hint: "The secret exists but has no value".to_string(),
                url: URL.to_string(),
            })?;

        // Convert bytes to string
        String::from_utf8(payload.data.to_vec()).map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: PROVIDER_NAME.to_string(),
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
