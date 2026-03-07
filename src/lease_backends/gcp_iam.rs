use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/gcp-iam";

pub struct GcpIamBackend {
    service_account_email: String,
    scopes: Vec<String>,
}

impl GcpIamBackend {
    pub fn new(service_account_email: String, scopes: Vec<String>) -> Self {
        Self {
            service_account_email,
            scopes,
        }
    }
}

#[async_trait]
impl LeaseBackend for GcpIamBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        // GCP's generateAccessToken API does not accept a label/session name,
        // so we log it for debugging. The label is still recorded in the ledger.
        tracing::debug!("Creating GCP IAM lease with label '{}'", label);
        let auth_manager =
            gcp_auth::provider()
                .await
                .map_err(|e| {
                    FnoxError::ProviderAuthFailed {
                provider: "GCP IAM".to_string(),
                details: e.to_string(),
                hint:
                    "Ensure GCP credentials are configured (gcloud auth, service account key, etc.)"
                        .to_string(),
                url: URL.to_string(),
            }
                })?;

        let token = auth_manager
            .token(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
            .map_err(|e| FnoxError::ProviderAuthFailed {
                provider: "GCP IAM".to_string(),
                details: e.to_string(),
                hint: "Failed to get caller credentials for IAM API".to_string(),
                url: URL.to_string(),
            })?;

        let bearer = token.as_str();
        let lifetime = format!("{}s", duration.as_secs());
        let url = format!(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken",
            self.service_account_email
        );

        let body = serde_json::json!({
            "scope": self.scopes,
            "lifetime": lifetime,
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .bearer_auth(bearer)
            .json(&body)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "GCP IAM".to_string(),
                details: e.to_string(),
                hint: "Failed to call IAM Credentials API".to_string(),
                url: URL.to_string(),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            if status.as_u16() == 403 || status.as_u16() == 401 {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "GCP IAM".to_string(),
                    details: body_text,
                    hint: format!(
                        "Check IAM permissions for impersonating '{}'",
                        self.service_account_email
                    ),
                    url: URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderApiError {
                provider: "GCP IAM".to_string(),
                details: format!("HTTP {}: {}", status, body_text),
                hint: "Check service account email and scopes".to_string(),
                url: URL.to_string(),
            });
        }

        let resp: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| FnoxError::ProviderInvalidResponse {
                    provider: "GCP IAM".to_string(),
                    details: e.to_string(),
                    hint: "Unexpected response from IAM Credentials API".to_string(),
                    url: URL.to_string(),
                })?;

        let access_token = resp["accessToken"]
            .as_str()
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "GCP IAM".to_string(),
                details: "Response missing 'accessToken' field".to_string(),
                hint: "Unexpected response from IAM Credentials API".to_string(),
                url: URL.to_string(),
            })?
            .to_string();

        let expire_time = resp["expireTime"].as_str().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        });

        let mut credentials = IndexMap::new();
        credentials.insert("CLOUDSDK_AUTH_ACCESS_TOKEN".to_string(), access_token);

        let lease_id = format!(
            "gcp-iam-{}-{}",
            self.service_account_email,
            chrono::Utc::now().timestamp_millis()
        );

        Ok(Lease {
            credentials,
            expires_at: expire_time,
            lease_id,
        })
    }

    fn max_lease_duration(&self) -> Duration {
        // GCP default max is 1 hour (3600s); can be extended to 12h with org policy
        Duration::from_secs(3600)
    }
}
