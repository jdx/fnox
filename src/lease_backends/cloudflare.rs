use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/cloudflare";
const API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareBackend {
    account_id: Option<String>,
    policies: Vec<CloudflarePolicy>,
    env_var: String,
}

/// A Cloudflare API token permission policy.
/// Maps to the Cloudflare API's `policies` array in POST /user/tokens.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CloudflarePolicy {
    /// "allow" or "deny"
    #[serde(default = "default_effect")]
    pub effect: String,
    /// Permission group IDs (UUIDs from Cloudflare's permission groups API)
    pub permission_groups: Vec<CloudflarePermissionGroup>,
    /// Resource scope, e.g. {"com.cloudflare.api.account.*": "*"}
    pub resources: IndexMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CloudflarePermissionGroup {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

fn default_effect() -> String {
    "allow".to_string()
}

impl CloudflareBackend {
    pub fn new(
        account_id: Option<String>,
        policies: Vec<CloudflarePolicy>,
        env_var: String,
    ) -> Self {
        Self {
            account_id,
            policies,
            env_var,
        }
    }

    fn get_api_token() -> Result<String> {
        std::env::var("CLOUDFLARE_API_TOKEN")
            .or_else(|_| std::env::var("CF_API_TOKEN"))
            .map_err(|_| FnoxError::ProviderAuthFailed {
                provider: "Cloudflare".to_string(),
                details: "No parent API token found".to_string(),
                hint: "Set CLOUDFLARE_API_TOKEN or CF_API_TOKEN with a token that has 'API Tokens: Edit' permission".to_string(),
                url: URL.to_string(),
            })
    }

    /// Build the policies array for the Cloudflare API request, substituting
    /// the account ID into resource keys that contain the `{account_id}` placeholder.
    fn build_api_policies(&self) -> Vec<serde_json::Value> {
        self.policies
            .iter()
            .map(|p| {
                let mut resources = serde_json::Map::new();
                for (key, value) in &p.resources {
                    let resolved_key = if let Some(account_id) = &self.account_id {
                        key.replace("{account_id}", account_id)
                    } else {
                        key.clone()
                    };
                    resources.insert(resolved_key, value.clone());
                }
                serde_json::json!({
                    "effect": p.effect,
                    "resources": resources,
                    "permission_groups": p.permission_groups.iter().map(|pg| {
                        let mut m = serde_json::Map::new();
                        m.insert("id".to_string(), serde_json::Value::String(pg.id.clone()));
                        if let Some(name) = &pg.name {
                            m.insert("name".to_string(), serde_json::Value::String(name.clone()));
                        }
                        serde_json::Value::Object(m)
                    }).collect::<Vec<_>>(),
                })
            })
            .collect()
    }
}

#[async_trait]
impl LeaseBackend for CloudflareBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let parent_token = Self::get_api_token()?;

        let now = chrono::Utc::now();
        let expires_on = now + chrono::Duration::seconds(duration.as_secs() as i64);

        let name = format!("fnox-lease-{label}");
        let policies = self.build_api_policies();

        let body = serde_json::json!({
            "name": name,
            "policies": policies,
            "not_before": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "expires_on": expires_on.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });

        let client = crate::http::http_client();
        let response = client
            .post(format!("{API_BASE}/user/tokens"))
            .bearer_auth(&parent_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Cloudflare".to_string(),
                details: e.to_string(),
                hint: "Failed to connect to Cloudflare API".to_string(),
                url: URL.to_string(),
            })?;

        let status = response.status();
        let resp: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| FnoxError::ProviderInvalidResponse {
                    provider: "Cloudflare".to_string(),
                    details: e.to_string(),
                    hint: "Unexpected response from Cloudflare API".to_string(),
                    url: URL.to_string(),
                })?;

        if !status.is_success() || !resp["success"].as_bool().unwrap_or(false) {
            let errors = resp["errors"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| e["message"].as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_else(|| format!("HTTP {status}"));

            if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Cloudflare".to_string(),
                    details: errors,
                    hint: "Check that your parent API token has 'API Tokens: Edit' permission"
                        .to_string(),
                    url: URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderApiError {
                provider: "Cloudflare".to_string(),
                details: errors,
                hint: "Check policies and account_id configuration".to_string(),
                url: URL.to_string(),
            });
        }

        let result = &resp["result"];
        let token_value =
            result["value"]
                .as_str()
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: "Cloudflare".to_string(),
                    details: "Response missing 'result.value' field".to_string(),
                    hint: "Unexpected response from Cloudflare API".to_string(),
                    url: URL.to_string(),
                })?;

        let token_id = result["id"]
            .as_str()
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Cloudflare".to_string(),
                details: "Response missing 'result.id' field".to_string(),
                hint: "Unexpected response from Cloudflare API".to_string(),
                url: URL.to_string(),
            })?;

        let mut credentials = IndexMap::new();
        credentials.insert(self.env_var.clone(), token_value.to_string());

        // Use the Cloudflare token ID as the lease ID for revocation
        let lease_id = token_id.to_string();

        Ok(Lease {
            credentials,
            expires_at: Some(expires_on),
            lease_id,
        })
    }

    async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        let parent_token = Self::get_api_token()?;

        let client = crate::http::http_client();
        let response = client
            .delete(format!("{API_BASE}/user/tokens/{lease_id}"))
            .bearer_auth(&parent_token)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Cloudflare".to_string(),
                details: e.to_string(),
                hint: "Failed to revoke Cloudflare API token".to_string(),
                url: URL.to_string(),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Cloudflare".to_string(),
                    details: body_text,
                    hint: "Check that your parent API token has 'API Tokens: Edit' permission"
                        .to_string(),
                    url: URL.to_string(),
                });
            }
            // 404 = token already deleted — treat as success
            if status.as_u16() != 404 {
                return Err(FnoxError::ProviderApiError {
                    provider: "Cloudflare".to_string(),
                    details: format!("HTTP {}: {}", status, body_text),
                    hint: "Failed to revoke Cloudflare API token".to_string(),
                    url: URL.to_string(),
                });
            }
        }

        Ok(())
    }

    fn max_lease_duration(&self) -> Duration {
        // Cloudflare doesn't enforce a hard max, but 24h is a reasonable default
        Duration::from_secs(24 * 3600)
    }
}
