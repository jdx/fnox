use crate::env;
use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/vault";

pub struct VaultBackend {
    address: String,
    token: String,
    secret_path: String,
    namespace: Option<String>,
    env_map: IndexMap<String, String>,
    method: String,
}

impl VaultBackend {
    pub fn new(
        address: Option<String>,
        token: Option<String>,
        secret_path: String,
        namespace: Option<String>,
        env_map: IndexMap<String, String>,
        method: String,
    ) -> Result<Self> {
        let address = address
            .or_else(|| {
                env::var("FNOX_VAULT_ADDR")
                    .or_else(|_| env::var("VAULT_ADDR"))
                    .ok()
            })
            .ok_or_else(|| FnoxError::Config(
                "Vault address not configured. Set 'address' in lease config or VAULT_ADDR env var.".to_string(),
            ))?;

        let token = token
            .or_else(|| {
                env::var("FNOX_VAULT_TOKEN")
                    .or_else(|_| env::var("VAULT_TOKEN"))
                    .ok()
            })
            .ok_or_else(|| FnoxError::ProviderAuthFailed {
                provider: "Vault".to_string(),
                details: "VAULT_TOKEN not set".to_string(),
                hint: "Set 'token' in lease config or VAULT_TOKEN env var".to_string(),
                url: URL.to_string(),
            })?;

        Ok(Self {
            address,
            token,
            secret_path,
            namespace,
            env_map,
            method,
        })
    }
}

#[async_trait]
impl LeaseBackend for VaultBackend {
    async fn create_lease(&self, duration: Duration, _label: &str) -> Result<Lease> {
        let url = format!(
            "{}/v1/{}",
            self.address.trim_end_matches('/'),
            self.secret_path
        );

        let client = crate::http::http_client();
        let ttl_value = format!("{}s", duration.as_secs());
        let mut request = if self.method.eq_ignore_ascii_case("post")
            || self.method.eq_ignore_ascii_case("put")
        {
            client
                .post(&url)
                .header("X-Vault-Token", &self.token)
                .json(&serde_json::json!({ "ttl": ttl_value }))
        } else {
            client
                .get(&url)
                .header("X-Vault-Token", &self.token)
                .query(&[("ttl", &ttl_value)])
        };

        if let Some(ns) = &self.namespace {
            request = request.header("X-Vault-Namespace", ns);
        }

        let response = request
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Vault".to_string(),
                details: e.to_string(),
                hint: "Failed to connect to Vault server".to_string(),
                url: URL.to_string(),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            if status.as_u16() == 403 || status.as_u16() == 401 {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Vault".to_string(),
                    details: body_text,
                    hint: "Check your Vault token has the required permissions".to_string(),
                    url: URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderApiError {
                provider: "Vault".to_string(),
                details: format!("HTTP {}: {}", status, body_text),
                hint: "Check secret_path and Vault configuration".to_string(),
                url: URL.to_string(),
            });
        }

        let resp: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| FnoxError::ProviderInvalidResponse {
                    provider: "Vault".to_string(),
                    details: e.to_string(),
                    hint: "Unexpected response from Vault".to_string(),
                    url: URL.to_string(),
                })?;

        let outer_data =
            resp["data"]
                .as_object()
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: "Vault".to_string(),
                    details: "Response missing 'data' field".to_string(),
                    hint: "Check that the secret_path is a valid dynamic secret engine path"
                        .to_string(),
                    url: URL.to_string(),
                })?;

        // KV v2 wraps the actual data in data.data; other engines put fields
        // directly in data.  Detect KV v2 by checking for a nested "data" object.
        let data = if let Some(inner) = outer_data.get("data").and_then(|v| v.as_object()) {
            inner
        } else {
            outer_data
        };

        let mut credentials = IndexMap::new();
        for (vault_key, env_var) in &self.env_map {
            if let Some(value) = data.get(vault_key).and_then(|v| v.as_str()) {
                credentials.insert(env_var.clone(), value.to_string());
            } else {
                tracing::warn!(
                    "Vault response missing key '{}' (from env_map); '{}' will not be set",
                    vault_key,
                    env_var
                );
            }
        }
        if credentials.is_empty() && !self.env_map.is_empty() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "Vault".to_string(),
                details: "No configured env_map keys found in Vault response data".to_string(),
                hint: "Check that env_map keys match the fields returned by the secret engine"
                    .to_string(),
                url: URL.to_string(),
            });
        }

        let lease_id = resp["lease_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                format!(
                    "vault-{}-{}",
                    self.secret_path,
                    chrono::Utc::now().timestamp_millis()
                )
            });

        // Vault KV v2 returns lease_duration=0 (static secrets have no lease).
        // Treat 0 as "no expiry" so the lease stays active until explicitly revoked.
        let lease_duration = resp["lease_duration"].as_i64().filter(|&secs| secs > 0);

        // Warn if Vault returned a different TTL than requested — many engines
        // (database, pki, rabbitmq) silently ignore the ?ttl query parameter
        // and use the role's configured default TTL instead.
        if let Some(actual_secs) = lease_duration {
            let requested_secs = duration.as_secs() as i64;
            let diff = (actual_secs - requested_secs).abs();
            if diff > 30 {
                tracing::warn!(
                    "Vault returned lease_duration={}s but {}s was requested; \
                     the Vault role may override the requested TTL",
                    actual_secs,
                    requested_secs
                );
            }
        }

        let expires_at =
            lease_duration.map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs));

        Ok(Lease {
            credentials,
            expires_at,
            lease_id,
        })
    }

    async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        let url = format!(
            "{}/v1/sys/leases/revoke",
            self.address.trim_end_matches('/')
        );

        let client = crate::http::http_client();
        let mut request = client
            .put(&url)
            .header("X-Vault-Token", &self.token)
            .json(&serde_json::json!({ "lease_id": lease_id }));

        if let Some(ns) = &self.namespace {
            request = request.header("X-Vault-Namespace", ns);
        }

        let response = request
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Vault".to_string(),
                details: e.to_string(),
                hint: "Failed to revoke Vault lease".to_string(),
                url: URL.to_string(),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            return Err(FnoxError::ProviderApiError {
                provider: "Vault".to_string(),
                details: format!("HTTP {}: {}", status, body_text),
                hint: "Failed to revoke Vault lease — check token permissions".to_string(),
                url: URL.to_string(),
            });
        }

        Ok(())
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(24 * 3600)
    }
}
