use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/oauth2-client-credentials";
const PROVIDER: &str = "OAuth2";

/// The token endpoint decides the real lifetime; this only bounds `duration`,
/// which is used when the endpoint omits `expires_in`.
const MAX_DURATION_SECS: u64 = 24 * 3600;

const CLIENT_SECRET_ENV: &str = "OAUTH2_CLIENT_SECRET";

/// All env var names the OAuth2 client credentials backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = &[CLIENT_SECRET_ENV];

pub fn check_prerequisites() -> Option<String> {
    if std::env::var(CLIENT_SECRET_ENV).is_ok() {
        None
    } else {
        Some(format!(
            "OAuth2 client secret not found. Set {CLIENT_SECRET_ENV} to the client's secret."
        ))
    }
}

pub fn required_env_vars() -> Vec<(&'static str, &'static str)> {
    vec![(CLIENT_SECRET_ENV, "OAuth2 client secret")]
}

/// How the client authenticates to the token endpoint (RFC 6749 section 2.3.1).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuthMethod {
    /// HTTP Basic header (`client_secret_basic`)
    #[default]
    Basic,
    /// `client_id` and `client_secret` in the form body (`client_secret_post`)
    Post,
}

pub struct Oauth2ClientCredentialsBackend {
    token_url: String,
    client_id: String,
    scope: Option<String>,
    audience: Option<String>,
    env_var: String,
    auth_method: ClientAuthMethod,
    params: IndexMap<String, String>,
    revocation_url: Option<String>,
}

impl Oauth2ClientCredentialsBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_url: String,
        client_id: String,
        scope: Option<String>,
        audience: Option<String>,
        env_var: String,
        auth_method: ClientAuthMethod,
        params: IndexMap<String, String>,
        revocation_url: Option<String>,
    ) -> Self {
        Self {
            token_url,
            client_id,
            scope,
            audience,
            env_var,
            auth_method,
            params,
            revocation_url,
        }
    }

    fn client_secret() -> Result<String> {
        std::env::var(CLIENT_SECRET_ENV).map_err(|_| FnoxError::ProviderAuthFailed {
            provider: PROVIDER.to_string(),
            details: "No client secret found".to_string(),
            hint: format!("Set {CLIENT_SECRET_ENV} to the OAuth2 client's secret"),
            url: URL.to_string(),
        })
    }

    /// Attach client authentication to a request whose form fields are `form`.
    fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
        form: &mut Vec<(String, String)>,
        secret: &str,
    ) -> reqwest::RequestBuilder {
        match self.auth_method {
            // RFC 6749 requires the credentials to be form-urlencoded before
            // they are base64-encoded into the header.
            ClientAuthMethod::Basic => request.basic_auth(
                urlencoding::encode(&self.client_id).into_owned(),
                Some(urlencoding::encode(secret).into_owned()),
            ),
            ClientAuthMethod::Post => {
                form.push(("client_id".to_string(), self.client_id.clone()));
                form.push(("client_secret".to_string(), secret.to_string()));
                request
            }
        }
    }
}

fn error_text(status: reqwest::StatusCode, body: &serde_json::Value) -> String {
    match (body["error"].as_str(), body["error_description"].as_str()) {
        (Some(error), Some(description)) => format!("{error}: {description}"),
        (Some(error), None) => error.to_string(),
        _ => format!("HTTP {status}"),
    }
}

#[async_trait]
impl LeaseBackend for Oauth2ClientCredentialsBackend {
    async fn create_lease(&self, duration: Duration, _label: &str) -> Result<Lease> {
        let secret = Self::client_secret()?;

        let mut form = vec![("grant_type".to_string(), "client_credentials".to_string())];
        if let Some(scope) = &self.scope {
            form.push(("scope".to_string(), scope.clone()));
        }
        if let Some(audience) = &self.audience {
            form.push(("audience".to_string(), audience.clone()));
        }
        for (key, value) in &self.params {
            form.push((key.clone(), value.clone()));
        }

        let client = crate::http::http_client();
        let request = self.authenticate(client.post(&self.token_url), &mut form, &secret);
        let response = request
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: format!("Failed to connect to the token endpoint {}", self.token_url),
                url: URL.to_string(),
            })?;

        let status = response.status();
        let body: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| FnoxError::ProviderInvalidResponse {
                    provider: PROVIDER.to_string(),
                    details: e.to_string(),
                    hint: "The token endpoint did not return JSON".to_string(),
                    url: URL.to_string(),
                })?;

        if !status.is_success() {
            let details = error_text(status, &body);
            return Err(if matches!(status.as_u16(), 400 | 401 | 403) {
                FnoxError::ProviderAuthFailed {
                    provider: PROVIDER.to_string(),
                    details,
                    hint: "Check client_id, the client secret, scope and audience".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: PROVIDER.to_string(),
                    details,
                    hint: "The token endpoint rejected the request".to_string(),
                    url: URL.to_string(),
                }
            });
        }

        let token =
            body["access_token"]
                .as_str()
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: PROVIDER.to_string(),
                    details: "Response missing 'access_token' field".to_string(),
                    hint: "Check that token_url is an OAuth2 token endpoint".to_string(),
                    url: URL.to_string(),
                })?;

        // Some servers send `expires_in` as a string.
        let ttl = body["expires_in"]
            .as_u64()
            .or_else(|| body["expires_in"].as_str().and_then(|s| s.parse().ok()))
            .map(Duration::from_secs)
            .unwrap_or(duration);
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(ttl.as_secs().min(i64::MAX as u64) as i64);

        let mut credentials = IndexMap::new();
        credentials.insert(self.env_var.clone(), token.to_string());

        // Hash the token so the ledger id is stable for debugging without
        // leaking the secret.
        let hash = blake3::hash(token.as_bytes());

        Ok(Lease {
            credentials,
            expires_at: Some(expires_at),
            lease_id: format!("oauth2-{}", &hash.to_hex()[..16]),
        })
    }

    async fn revoke_lease(
        &self,
        _lease_id: &str,
        credentials: Option<&IndexMap<String, String>>,
    ) -> Result<()> {
        // Without a revocation endpoint the token simply expires.
        let Some(revocation_url) = &self.revocation_url else {
            return Ok(());
        };
        // No cached token means it was never stored or is already gone.
        let Some(token) = credentials.and_then(|creds| creds.get(&self.env_var)) else {
            return Ok(());
        };

        let secret = Self::client_secret()?;
        let mut form = vec![
            ("token".to_string(), token.clone()),
            ("token_type_hint".to_string(), "access_token".to_string()),
        ];
        let client = crate::http::http_client();
        let request = self.authenticate(client.post(revocation_url), &mut form, &secret);
        let response =
            request
                .form(&form)
                .send()
                .await
                .map_err(|e| FnoxError::ProviderApiError {
                    provider: PROVIDER.to_string(),
                    details: e.to_string(),
                    hint: format!("Failed to connect to the revocation endpoint {revocation_url}"),
                    url: URL.to_string(),
                })?;

        // RFC 7009: 200 even for unknown or already-revoked tokens.
        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("HTTP {status}: {body_text}"),
                hint: "Failed to revoke OAuth2 access token".to_string(),
                url: URL.to_string(),
            });
        }
        Ok(())
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(MAX_DURATION_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_oauth_error_shapes() {
        let status = reqwest::StatusCode::UNAUTHORIZED;
        let both =
            serde_json::json!({"error": "invalid_client", "error_description": "bad secret"});
        assert_eq!(error_text(status, &both), "invalid_client: bad secret");
        let only = serde_json::json!({"error": "invalid_scope"});
        assert_eq!(error_text(status, &only), "invalid_scope");
        assert_eq!(
            error_text(status, &serde_json::Value::Null),
            "HTTP 401 Unauthorized"
        );
    }

    #[test]
    fn defaults_to_basic_client_auth() {
        assert_eq!(ClientAuthMethod::default(), ClientAuthMethod::Basic);
    }
}
