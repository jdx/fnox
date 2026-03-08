use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/cloudflare";
const API_BASE: &str = "https://api.cloudflare.com/client/v4";
const MAX_TOKEN_NAME_LEN: usize = 100;
const TOKEN_NAME_PREFIX: &str = "fnox-lease-";

pub struct CloudflareBackend {
    token_type: CloudflareTokenType,
    account_id: Option<String>,
    policies: Option<Vec<CloudflarePolicy>>,
    env_var: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum CloudflareTokenType {
    /// User-owned token (POST /user/tokens)
    #[default]
    User,
    /// Account-owned token (POST /accounts/{account_id}/tokens)
    Account,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum CloudflarePolicyEffect {
    #[default]
    Allow,
    Deny,
}

/// A Cloudflare API token permission policy.
/// Maps to the Cloudflare API's `policies` array in POST /user/tokens.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CloudflarePolicy {
    #[serde(default)]
    pub effect: CloudflarePolicyEffect,
    /// Permission group IDs (UUIDs from Cloudflare's permission groups API)
    pub permission_groups: Vec<CloudflarePermissionGroup>,
    /// Resource scope, e.g. {"com.cloudflare.api.account.*": "*"}
    pub resources: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CloudflarePermissionGroup {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl CloudflareBackend {
    pub fn new(
        token_type: CloudflareTokenType,
        account_id: Option<String>,
        policies: Option<Vec<CloudflarePolicy>>,
        env_var: String,
    ) -> Result<Self> {
        if matches!(token_type, CloudflareTokenType::Account) && account_id.is_none() {
            return Err(FnoxError::Config(
                "Cloudflare backend: 'account_id' is required when token_type is 'account'."
                    .to_string(),
            ));
        }
        Ok(Self {
            token_type,
            account_id,
            policies,
            env_var,
        })
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

    /// Returns the tokens API base path based on `token_type`.
    fn tokens_path(&self) -> String {
        match self.token_type {
            CloudflareTokenType::Account => {
                let id = self.account_id.as_ref().expect("validated in new()");
                format!("{API_BASE}/accounts/{id}/tokens")
            }
            CloudflareTokenType::User => format!("{API_BASE}/user/tokens"),
        }
    }

    /// Build the policies array for the Cloudflare API request, substituting
    /// the account ID into resource keys that contain the `{account_id}` placeholder.
    fn build_api_policies(
        policies: &[CloudflarePolicy],
        account_id: &Option<String>,
    ) -> Result<Vec<serde_json::Value>> {
        if policies.is_empty() {
            return Err(FnoxError::Config(
                "Cloudflare backend: 'policies' must contain at least one policy.".to_string(),
            ));
        }
        let mut result = Vec::with_capacity(policies.len());
        for p in policies {
            if p.permission_groups.is_empty() {
                return Err(FnoxError::Config(
                    "Cloudflare backend: each policy must have at least one permission group."
                        .to_string(),
                ));
            }
            let mut resources = serde_json::Map::new();
            for (key, value) in &p.resources {
                if key.contains("{account_id}") && account_id.is_none() {
                    return Err(FnoxError::Config(
                        "Resource key contains '{account_id}' placeholder but 'account_id' \
                         is not set in the Cloudflare backend config."
                            .to_string(),
                    ));
                }
                let resolved_key = if let Some(account_id) = account_id {
                    key.replace("{account_id}", account_id)
                } else {
                    key.clone()
                };
                resources.insert(resolved_key, serde_json::Value::String(value.clone()));
            }
            result.push(serde_json::json!({
                "effect": p.effect,
                "resources": resources,
                "permission_groups": p.permission_groups,
            }));
        }
        Ok(result)
    }

    /// Fetch the parent token's policies from the Cloudflare API.
    /// Always uses the /user/tokens endpoint for verify and details — the
    /// /accounts/{id}/tokens/verify endpoint does not exist.
    async fn fetch_parent_policies(parent_token: &str) -> Result<Vec<serde_json::Value>> {
        let user_tokens_path = format!("{API_BASE}/user/tokens");
        let client = crate::http::http_client();

        // Step 1: verify token to get its ID
        let verify_resp: serde_json::Value = client
            .get(format!("{user_tokens_path}/verify"))
            .bearer_auth(parent_token)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Cloudflare".to_string(),
                details: e.to_string(),
                hint: "Failed to verify parent token".to_string(),
                url: URL.to_string(),
            })?
            .json()
            .await
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Cloudflare".to_string(),
                details: e.to_string(),
                hint: "Unexpected response from Cloudflare verify endpoint".to_string(),
                url: URL.to_string(),
            })?;

        let token_id = verify_resp["result"]["id"].as_str().ok_or_else(|| {
            FnoxError::ProviderInvalidResponse {
                provider: "Cloudflare".to_string(),
                details: "Verify response missing 'result.id'".to_string(),
                hint: "Check that the parent token is valid".to_string(),
                url: URL.to_string(),
            }
        })?;

        // Step 2: fetch full token details including policies
        let details_resp: serde_json::Value = client
            .get(format!("{user_tokens_path}/{token_id}"))
            .bearer_auth(parent_token)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Cloudflare".to_string(),
                details: e.to_string(),
                hint: "Failed to fetch parent token details".to_string(),
                url: URL.to_string(),
            })?
            .json()
            .await
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Cloudflare".to_string(),
                details: e.to_string(),
                hint: "Unexpected response from Cloudflare token details endpoint".to_string(),
                url: URL.to_string(),
            })?;

        let policies = details_resp["result"]["policies"]
            .as_array()
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Cloudflare".to_string(),
                details: "Token details response missing 'result.policies'".to_string(),
                hint: "Check that the parent token is valid and accessible".to_string(),
                url: URL.to_string(),
            })?;

        // Clean up inherited policies for use as child token config:
        // 1. Only extract fields the create endpoint accepts (effect, resources,
        //    permission_groups) — drop server-generated fields like id, status,
        //    created_on, modified_on which would cause validation errors.
        // 2. Remove "API Tokens" permission groups — Cloudflare forbids
        //    sub-tokens from managing other tokens.
        // 3. Only keep permission group `id` (strip `name` and other metadata).
        let cleaned: Vec<serde_json::Value> = policies
            .iter()
            .filter_map(|p| {
                let obj = p.as_object()?;

                // Filter out token-management permission groups, keeping only id
                let groups: Vec<serde_json::Value> = obj
                    .get("permission_groups")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .filter(|g| {
                        let name = g["name"].as_str().unwrap_or("");
                        !name.contains("API Tokens")
                    })
                    .filter_map(|g| {
                        let id = g["id"].as_str()?;
                        Some(serde_json::json!({ "id": id }))
                    })
                    .collect();

                // Drop the entire policy if no permission groups remain
                if groups.is_empty() {
                    return None;
                }

                Some(serde_json::json!({
                    "effect": obj.get("effect").cloned().unwrap_or(serde_json::json!("allow")),
                    "resources": obj.get("resources").cloned().unwrap_or(serde_json::json!({})),
                    "permission_groups": groups,
                }))
            })
            .collect();

        if cleaned.is_empty() {
            return Err(FnoxError::Config(
                "Parent token only has 'API Tokens' permissions which cannot be inherited. \
                 Configure explicit policies or use a parent token with additional permissions."
                    .to_string(),
            ));
        }

        Ok(cleaned)
    }
}

#[async_trait]
impl LeaseBackend for CloudflareBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let parent_token = Self::get_api_token()?;
        let tokens_path = self.tokens_path();

        let now = chrono::Utc::now();
        let expires_on =
            now + chrono::Duration::seconds(duration.as_secs().min(i64::MAX as u64) as i64);

        let raw_name = format!("{TOKEN_NAME_PREFIX}{label}");
        let name = if raw_name.chars().count() > MAX_TOKEN_NAME_LEN {
            raw_name.chars().take(MAX_TOKEN_NAME_LEN).collect()
        } else {
            raw_name
        };

        // Use configured policies, or inherit from the parent token
        let policies = if let Some(ref configured) = self.policies {
            Self::build_api_policies(configured, &self.account_id)?
        } else {
            tracing::debug!("No policies configured; inheriting from parent token");
            Self::fetch_parent_policies(&parent_token).await?
        };

        let body = serde_json::json!({
            "name": name,
            "policies": policies,
            "expires_on": expires_on.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });

        let client = crate::http::http_client();
        let response = client
            .post(&tokens_path)
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
                .and_then(|arr| {
                    let msgs: Vec<_> = arr.iter().filter_map(|e| e["message"].as_str()).collect();
                    if msgs.is_empty() {
                        None
                    } else {
                        Some(msgs.join("; "))
                    }
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
        let tokens_path = self.tokens_path();

        let client = crate::http::http_client();
        let response = client
            .delete(format!("{tokens_path}/{lease_id}"))
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
