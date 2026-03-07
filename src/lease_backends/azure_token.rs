use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/lease-backends/azure-token";

pub struct AzureTokenBackend {
    scope: String,
    env_var: String,
}

impl AzureTokenBackend {
    pub fn new(scope: String, env_var: String) -> Self {
        Self { scope, env_var }
    }

    fn build_credential(&self) -> Result<Arc<dyn TokenCredential>> {
        let tenant_id =
            std::env::var("AZURE_TENANT_ID").map_err(|_| FnoxError::ProviderAuthFailed {
                provider: "Azure Token".to_string(),
                details: "AZURE_TENANT_ID not set".to_string(),
                hint: "Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID".to_string(),
                url: URL.to_string(),
            })?;
        let client_id =
            std::env::var("AZURE_CLIENT_ID").map_err(|_| FnoxError::ProviderAuthFailed {
                provider: "Azure Token".to_string(),
                details: "AZURE_CLIENT_ID not set".to_string(),
                hint: "Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID".to_string(),
                url: URL.to_string(),
            })?;
        let client_secret =
            std::env::var("AZURE_CLIENT_SECRET").map_err(|_| FnoxError::ProviderAuthFailed {
                provider: "Azure Token".to_string(),
                details: "AZURE_CLIENT_SECRET not set".to_string(),
                hint: "Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID".to_string(),
                url: URL.to_string(),
            })?;

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
        Ok(cred)
    }
}

#[async_trait]
impl LeaseBackend for AzureTokenBackend {
    async fn create_lease(&self, _duration: Duration, _label: &str) -> Result<Lease> {
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

        let mut credentials = HashMap::new();
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
