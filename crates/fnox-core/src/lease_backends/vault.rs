use crate::env;
use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::json;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/vault";

/// All env var names the Vault backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = &[
    "VAULT_ADDR",
    "FNOX_VAULT_ADDR",
    "VAULT_TOKEN",
    "FNOX_VAULT_TOKEN",
    "VAULT_NAMESPACE",
    "FNOX_VAULT_NAMESPACE",
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "VAULT_SKIP_VERIFY",
    "VAULT_CLIENT_CERT",
    "VAULT_CLIENT_KEY",
    "VAULT_TLS_SERVER_NAME",
];

pub fn check_prerequisites(
    address: &Option<String>,
    token: &Option<String>,
    credential_command: &Option<String>,
) -> Option<String> {
    let has_addr = address.is_some()
        || std::env::var("VAULT_ADDR").is_ok()
        || std::env::var("FNOX_VAULT_ADDR").is_ok();
    let has_token = token.is_some()
        || std::env::var("VAULT_TOKEN").is_ok()
        || std::env::var("FNOX_VAULT_TOKEN").is_ok()
        || credential_command.is_some();
    match (has_addr, has_token) {
        (false, false) => {
            Some("Vault address and token not found. Set VAULT_ADDR and VAULT_TOKEN.".to_string())
        }
        (false, true) => Some("Vault address not found. Set VAULT_ADDR.".to_string()),
        (true, false) => Some("Vault token not found. Set VAULT_TOKEN.".to_string()),
        (true, true) => None,
    }
}

pub fn required_env_vars(
    address: &Option<String>,
    token: &Option<String>,
    credential_command: &Option<String>,
) -> Vec<(&'static str, &'static str)> {
    let mut vars = vec![];
    if address.is_none() {
        vars.push((
            "VAULT_ADDR",
            "Vault server address (e.g., http://localhost:8200)",
        ));
    }
    if token.is_none() && credential_command.is_none() {
        vars.push(("VAULT_TOKEN", "Vault authentication token"));
    }
    vars
}

pub struct VaultBackend {
    address: String,
    token: Option<String>,
    credential_command: Option<String>,
    secret_path: String,
    namespace: Option<String>,
    env_map: IndexMap<String, String>,
    method: String,
}

impl VaultBackend {
    pub fn new(
        address: Option<String>,
        token: Option<String>,
        credential_command: Option<String>,
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

        let token = token.or_else(|| {
            env::var("FNOX_VAULT_TOKEN")
                .or_else(|_| env::var("VAULT_TOKEN"))
                .ok()
        });

        if token.is_none() && credential_command.is_none() {
            return Err(FnoxError::ProviderAuthFailed {
                provider: "Vault".to_string(),
                details: "VAULT_TOKEN not set".to_string(),
                hint: "Set 'token' in lease config, VAULT_TOKEN env var, or credential_command"
                    .to_string(),
                url: URL.to_string(),
            });
        }

        if env_map.is_empty() {
            return Err(FnoxError::Config(
                "Vault backend: 'env_map' must contain at least one entry \
                 mapping a Vault response key to an environment variable name."
                    .to_string(),
            ));
        }

        let namespace = namespace.or_else(vault_namespace);

        Ok(Self {
            address,
            token,
            credential_command,
            secret_path,
            namespace,
            env_map,
            method,
        })
    }

    fn credential_command_context(&self) -> serde_json::Value {
        json!({
            "address": self.address,
            "secret_path": self.secret_path,
            "namespace": self.namespace,
        })
    }

    fn credential_command_envs(&self) -> Vec<(&str, String)> {
        let mut envs = vec![("VAULT_ADDR", self.address.clone())];
        if let Some(namespace) = &self.namespace {
            envs.push(("VAULT_NAMESPACE", namespace.clone()));
        }
        envs
    }

    async fn token(&self) -> Result<String> {
        if let Some(token) = &self.token {
            return Ok(token.clone());
        }

        let command =
            self.credential_command
                .as_ref()
                .ok_or_else(|| FnoxError::ProviderAuthFailed {
                    provider: "Vault".to_string(),
                    details: "VAULT_TOKEN not set".to_string(),
                    hint: "Set 'token' in lease config, VAULT_TOKEN env var, or credential_command"
                        .to_string(),
                    url: URL.to_string(),
                })?;

        let envs = self.credential_command_envs();

        crate::credential_command::run(
            "Vault",
            command,
            self.credential_command_context(),
            &envs,
            crate::credential_command::DEFAULT_TIMEOUT,
            URL,
        )
        .await
    }

    fn invalidate_credential_command(&self) -> Result<()> {
        if self.token.is_some() {
            return Ok(());
        }

        let Some(command) = &self.credential_command else {
            return Ok(());
        };

        crate::credential_command::invalidate(
            "Vault",
            command,
            self.credential_command_context(),
            &self.credential_command_envs(),
            URL,
        )
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
        let token = self.token().await?;
        let mut request = if self.method.eq_ignore_ascii_case("post")
            || self.method.eq_ignore_ascii_case("put")
        {
            client
                .post(&url)
                .header("X-Vault-Token", &token)
                .json(&serde_json::json!({ "ttl": ttl_value }))
        } else {
            client
                .get(&url)
                .header("X-Vault-Token", &token)
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
                self.invalidate_credential_command()?;
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
            .unwrap_or_else(|| super::generate_lease_id(&format!("vault-{}", self.secret_path)));

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

    async fn revoke_lease(
        &self,
        lease_id: &str,
        _credentials: Option<&IndexMap<String, String>>,
    ) -> Result<()> {
        let url = format!(
            "{}/v1/sys/leases/revoke",
            self.address.trim_end_matches('/')
        );

        let client = crate::http::http_client();
        let token = self.token().await?;
        let mut request = client
            .put(&url)
            .header("X-Vault-Token", &token)
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
            if status.as_u16() == 403 || status.as_u16() == 401 {
                self.invalidate_credential_command()?;
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Vault".to_string(),
                    details: body_text,
                    hint: "Vault token needs 'update' permission on 'sys/leases/revoke'. \
                           Add `path \"sys/leases/revoke\" { capabilities = [\"update\"] }` \
                           to your Vault policy."
                        .to_string(),
                    url: URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderApiError {
                provider: "Vault".to_string(),
                details: format!("HTTP {}: {}", status, body_text),
                hint: "Failed to revoke Vault lease".to_string(),
                url: URL.to_string(),
            });
        }

        Ok(())
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(24 * 3600)
    }
}

fn vault_namespace() -> Option<String> {
    env::var("FNOX_VAULT_NAMESPACE")
        .or_else(|_| env::var("VAULT_NAMESPACE"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_vault_namespace_env_fallback() {
        env::set_var("FNOX_VAULT_NAMESPACE", "admin/test");
        env::remove_var("VAULT_NAMESPACE");

        let mut env_map = IndexMap::new();
        env_map.insert("access_key".to_string(), "AWS_ACCESS_KEY_ID".to_string());

        let backend = VaultBackend::new(
            Some("https://vault.example.com".to_string()),
            Some("token".to_string()),
            None,
            "secret/data/fnox".to_string(),
            None,
            env_map,
            "get".to_string(),
        )
        .unwrap();

        assert_eq!(backend.namespace.as_deref(), Some("admin/test"));

        env::remove_var("FNOX_VAULT_NAMESPACE");
    }
}
