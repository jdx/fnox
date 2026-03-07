use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use indexmap::IndexMap;
use std::sync::Arc;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/azure-token";

pub struct AzureTokenBackend {
    scope: String,
    env_var: String,
}

impl AzureTokenBackend {
    pub fn new(scope: String, env_var: String) -> Self {
        Self { scope, env_var }
    }

    fn build_credential(&self) -> Result<Arc<dyn TokenCredential>> {
        // Prefer ClientSecretCredential from env vars
        if let (Ok(tenant_id), Ok(client_id), Ok(client_secret)) = (
            std::env::var("AZURE_TENANT_ID"),
            std::env::var("AZURE_CLIENT_ID"),
            std::env::var("AZURE_CLIENT_SECRET"),
        ) {
            let cred = azure_identity::ClientSecretCredential::new(
                &tenant_id,
                client_id,
                client_secret.into(),
                None,
            )
            .map_err(|e: azure_core::Error| FnoxError::ProviderAuthFailed {
                provider: "Azure Token".to_string(),
                details: e.to_string(),
                hint: "Check AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET".to_string(),
                url: URL.to_string(),
            })?;
            return Ok(cred);
        }

        // Fall back to DeveloperToolsCredential (az CLI)
        let cred = azure_identity::DeveloperToolsCredential::new(None).map_err(
            |e: azure_core::Error| FnoxError::ProviderAuthFailed {
                provider: "Azure Token".to_string(),
                details: e.to_string(),
                hint: "Run 'az login' or set AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID"
                    .to_string(),
                url: URL.to_string(),
            },
        )?;
        Ok(cred)
    }
}

#[async_trait]
impl LeaseBackend for AzureTokenBackend {
    async fn create_lease(&self, duration: Duration, _label: &str) -> Result<Lease> {
        if duration < Duration::from_secs(3600) {
            tracing::warn!(
                "Azure controls token lifetime (~1h); requested duration {}m will be ignored",
                duration.as_secs() / 60
            );
        }
        let credential = self.build_credential()?;

        let token_response =
            credential
                .get_token(&[&self.scope], None)
                .await
                .map_err(|e: azure_core::Error| FnoxError::ProviderAuthFailed {
                    provider: "Azure Token".to_string(),
                    details: e.to_string(),
                    hint: "Failed to acquire Azure token. Check credentials and scope.".to_string(),
                    url: URL.to_string(),
                })?;

        let expires_at =
            chrono::DateTime::from_timestamp(token_response.expires_on.unix_timestamp(), 0)
                .or_else(|| {
                    tracing::warn!("Azure token returned an out-of-range expiration timestamp");
                    None
                });

        let mut credentials = IndexMap::new();
        credentials.insert(
            self.env_var.clone(),
            token_response.token.secret().to_string(),
        );

        let lease_id = format!("azure-token-{}", chrono::Utc::now().timestamp_millis());

        Ok(Lease {
            credentials,
            expires_at,
            lease_id,
        })
    }

    fn max_lease_duration(&self) -> Duration {
        // Azure controls token lifetime (~1 hour), not configurable by caller
        Duration::from_secs(3600)
    }
}
