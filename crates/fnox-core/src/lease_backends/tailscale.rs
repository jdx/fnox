use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend, env_credential, require_secure_url};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/tailscale";
const PROVIDER: &str = "Tailscale";
const API_BASE: &str = "https://api.tailscale.com";

/// Tailscale auth keys expire after at most 90 days.
const MAX_DURATION_SECS: u64 = 90 * 24 * 3600;

/// Tailscale truncates key descriptions at 50 characters.
const MAX_DESCRIPTION_LEN: usize = 50;

/// All env var names the Tailscale backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = &[
    "TAILSCALE_API_KEY",
    "TAILSCALE_OAUTH_CLIENT_ID",
    "TAILSCALE_OAUTH_CLIENT_SECRET",
];

pub fn check_prerequisites() -> Option<String> {
    if Credentials::from_env().is_some() {
        None
    } else {
        Some("Tailscale credentials not found. Set TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET (an OAuth client with the 'auth_keys' scope), or TAILSCALE_API_KEY.".to_string())
    }
}

pub fn required_env_vars() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "TAILSCALE_OAUTH_CLIENT_ID",
            "Tailscale OAuth client ID with the 'auth_keys' scope (or set TAILSCALE_API_KEY instead)",
        ),
        (
            "TAILSCALE_OAUTH_CLIENT_SECRET",
            "Tailscale OAuth client secret",
        ),
    ]
}

/// Bootstrap credentials for the Tailscale API.
enum Credentials {
    ApiKey(String),
    OauthClient { id: String, secret: String },
}

impl Credentials {
    fn from_env() -> Option<Self> {
        if let Some(key) = env_credential("TAILSCALE_API_KEY") {
            return Some(Self::ApiKey(key));
        }
        let id = env_credential("TAILSCALE_OAUTH_CLIENT_ID")?;
        let secret = env_credential("TAILSCALE_OAUTH_CLIENT_SECRET")?;
        Some(Self::OauthClient { id, secret })
    }
}

pub struct TailscaleBackend {
    tailnet: String,
    api_base: String,
    tags: Vec<String>,
    reusable: bool,
    ephemeral: bool,
    preauthorized: bool,
    env_var: String,
}

impl TailscaleBackend {
    pub fn new(
        tailnet: String,
        api_base: Option<String>,
        tags: Vec<String>,
        reusable: bool,
        ephemeral: bool,
        preauthorized: bool,
        env_var: String,
    ) -> Result<Self> {
        let api_base = api_base
            .unwrap_or_else(|| API_BASE.to_string())
            .trim_end_matches('/')
            .to_string();
        // Credentials are sent to this URL.
        require_secure_url(PROVIDER, "api_base", &api_base)?;
        Ok(Self {
            tailnet,
            api_base,
            tags,
            reusable,
            ephemeral,
            preauthorized,
            env_var,
        })
    }

    fn keys_url(&self) -> String {
        format!(
            "{}/api/v2/tailnet/{}/keys",
            self.api_base,
            urlencoding::encode(&self.tailnet)
        )
    }

    /// Attach credentials to a request. An OAuth client is exchanged for an
    /// access token first; an API key is sent as the Basic auth username.
    async fn authorize(&self, request: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
        let credentials = Credentials::from_env().ok_or_else(|| FnoxError::ProviderAuthFailed {
            provider: PROVIDER.to_string(),
            details: "No Tailscale credentials found".to_string(),
            hint: "Set TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET, or TAILSCALE_API_KEY"
                .to_string(),
            url: URL.to_string(),
        })?;
        match credentials {
            Credentials::ApiKey(key) => Ok(request.basic_auth(key, Some(""))),
            Credentials::OauthClient { id, secret } => {
                let token = self.exchange_oauth_client(&id, &secret).await?;
                Ok(request.bearer_auth(token))
            }
        }
    }

    async fn exchange_oauth_client(&self, id: &str, secret: &str) -> Result<String> {
        let client = crate::http::credential_client();
        let response = client
            .post(format!("{}/api/v2/oauth/token", self.api_base))
            .form(&[
                ("client_id", id),
                ("client_secret", secret),
                ("grant_type", "client_credentials"),
            ])
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: "Failed to connect to Tailscale API".to_string(),
                url: URL.to_string(),
            })?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(FnoxError::ProviderAuthFailed {
                provider: PROVIDER.to_string(),
                details: error_text(status, &text),
                hint: "Check the OAuth client ID and secret".to_string(),
                url: URL.to_string(),
            });
        }
        let body: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: "Unexpected response from Tailscale OAuth endpoint".to_string(),
                url: URL.to_string(),
            })?;
        body["access_token"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER.to_string(),
                details: "Response missing 'access_token' field".to_string(),
                hint: "Unexpected response from Tailscale OAuth endpoint".to_string(),
                url: URL.to_string(),
            })
    }
}

fn error_text(status: reqwest::StatusCode, body: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    match parsed["message"]
        .as_str()
        .or_else(|| parsed["error_description"].as_str())
        .or_else(|| parsed["error"].as_str())
    {
        Some(message) => message.to_string(),
        None if body.trim().is_empty() => format!("HTTP {status}"),
        None => format!("HTTP {status}: {}", body.trim()),
    }
}

#[async_trait]
impl LeaseBackend for TailscaleBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let mut create = serde_json::json!({
            "reusable": self.reusable,
            "ephemeral": self.ephemeral,
            "preauthorized": self.preauthorized,
        });
        if !self.tags.is_empty() {
            create["tags"] = serde_json::json!(self.tags);
        }
        let body = serde_json::json!({
            "capabilities": { "devices": { "create": create } },
            "expirySeconds": duration.as_secs(),
            "description": label.chars().take(MAX_DESCRIPTION_LEN).collect::<String>(),
        });

        let client = crate::http::credential_client();
        let request = self.authorize(client.post(self.keys_url())).await?;
        let response =
            request
                .json(&body)
                .send()
                .await
                .map_err(|e| FnoxError::ProviderApiError {
                    provider: PROVIDER.to_string(),
                    details: e.to_string(),
                    hint: "Failed to connect to Tailscale API".to_string(),
                    url: URL.to_string(),
                })?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            let details = error_text(status, &text);
            return Err(if matches!(status.as_u16(), 401 | 403) {
                FnoxError::ProviderAuthFailed {
                    provider: PROVIDER.to_string(),
                    details,
                    hint: "Check that the credentials can write auth keys (OAuth scope 'auth_keys') and that the tags are owned by the client"
                        .to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: PROVIDER.to_string(),
                    details,
                    hint: "Check tailnet and tags configuration".to_string(),
                    url: URL.to_string(),
                }
            });
        }

        let resp: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: "Unexpected response from Tailscale API".to_string(),
                url: URL.to_string(),
            })?;
        let missing = |field: &str| FnoxError::ProviderInvalidResponse {
            provider: PROVIDER.to_string(),
            details: format!("Response missing '{field}' field"),
            hint: "Unexpected response from Tailscale API".to_string(),
            url: URL.to_string(),
        };
        let key = resp["key"].as_str().ok_or_else(|| missing("key"))?;
        let key_id = resp["id"].as_str().ok_or_else(|| missing("id"))?;

        // Fall back to the requested duration so a missing `expires` can never
        // make the ledger treat the key as never-expiring.
        let expires_at = resp["expires"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|| {
                chrono::Utc::now()
                    + chrono::Duration::seconds(duration.as_secs().min(i64::MAX as u64) as i64)
            });

        let mut credentials = IndexMap::new();
        credentials.insert(self.env_var.clone(), key.to_string());

        Ok(Lease {
            credentials,
            expires_at: Some(expires_at),
            lease_id: key_id.to_string(),
        })
    }

    async fn revoke_lease(
        &self,
        lease_id: &str,
        _credentials: Option<&IndexMap<String, String>>,
    ) -> Result<()> {
        let client = crate::http::credential_client();
        let request = self
            .authorize(client.delete(format!(
                "{}/{}",
                self.keys_url(),
                urlencoding::encode(lease_id)
            )))
            .await?;
        let response = request
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: "Failed to connect to Tailscale API for key revocation".to_string(),
                url: URL.to_string(),
            })?;

        let status = response.status();
        // 404 = key already expired or deleted
        if status.is_success() || status.as_u16() == 404 {
            return Ok(());
        }
        let text = response.text().await.unwrap_or_default();
        let details = error_text(status, &text);
        Err(if matches!(status.as_u16(), 401 | 403) {
            FnoxError::ProviderAuthFailed {
                provider: PROVIDER.to_string(),
                details,
                hint: "Check that the credentials can write auth keys".to_string(),
                url: URL.to_string(),
            }
        } else {
            FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details,
                hint: "Failed to revoke Tailscale auth key".to_string(),
                url: URL.to_string(),
            }
        })
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(MAX_DURATION_SECS)
    }

    /// A single-use key is spent by the first device that registers with it, so
    /// handing the cached key to a later command would give it a dead key.
    fn cacheable(&self) -> bool {
        self.reusable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(tailnet: &str, api_base: Option<&str>) -> TailscaleBackend {
        TailscaleBackend::new(
            tailnet.to_string(),
            api_base.map(str::to_string),
            vec![],
            false,
            true,
            true,
            "TS_AUTHKEY".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn only_reusable_keys_are_cacheable() {
        let build = |reusable| {
            TailscaleBackend::new(
                "-".to_string(),
                None,
                vec![],
                reusable,
                true,
                true,
                "TS_AUTHKEY".to_string(),
            )
            .unwrap()
        };
        assert!(!build(false).cacheable());
        assert!(build(true).cacheable());
    }

    #[test]
    fn rejects_cleartext_api_base_except_on_loopback() {
        let build = |base: &str| {
            TailscaleBackend::new(
                "-".to_string(),
                Some(base.to_string()),
                vec![],
                false,
                true,
                true,
                "TS_AUTHKEY".to_string(),
            )
        };
        assert!(build("http://api.example.com").is_err());
        assert!(build("https://api.example.com").is_ok());
        assert!(build("http://127.0.0.1:9").is_ok());
    }

    #[test]
    fn builds_the_keys_url() {
        assert_eq!(
            backend("-", None).keys_url(),
            "https://api.tailscale.com/api/v2/tailnet/-/keys"
        );
        assert_eq!(
            backend("example.org", Some("http://127.0.0.1:1/")).keys_url(),
            "http://127.0.0.1:1/api/v2/tailnet/example.org/keys"
        );
    }

    #[test]
    fn reads_error_message_shapes() {
        let status = reqwest::StatusCode::FORBIDDEN;
        assert_eq!(error_text(status, r#"{"message":"denied"}"#), "denied");
        assert_eq!(
            error_text(status, r#"{"error_description":"bad client"}"#),
            "bad client"
        );
        assert_eq!(error_text(status, ""), "HTTP 403 Forbidden");
    }
}
