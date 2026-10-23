use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend, env_credential, require_secure_url};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/oauth2-client-credentials";
const PROVIDER: &str = "OAuth2";

/// The token endpoint decides the real lifetime; this only bounds `duration`,
/// which is used when the endpoint omits `expires_in`.
const MAX_DURATION_SECS: u64 = 24 * 3600;

/// Upper bound for a server-supplied `expires_in` (ten years), so a bogus value
/// cannot overflow date arithmetic.
const MAX_TTL_SECS: u64 = 10 * 365 * 24 * 3600;

const CLIENT_SECRET_ENV: &str = "OAUTH2_CLIENT_SECRET";

/// All env var names the OAuth2 client credentials backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = &[CLIENT_SECRET_ENV];

pub fn check_prerequisites() -> Option<String> {
    if env_credential(CLIENT_SECRET_ENV).is_some() {
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
    ) -> Result<Self> {
        // The client secret is sent to these URLs.
        require_secure_url(PROVIDER, "token_url", &token_url)?;
        if let Some(url) = &revocation_url {
            require_secure_url(PROVIDER, "revocation_url", url)?;
        }
        Ok(Self {
            token_url,
            client_id,
            scope,
            audience,
            env_var,
            auth_method,
            params,
            revocation_url,
        })
    }

    fn client_secret() -> Result<String> {
        env_credential(CLIENT_SECRET_ENV).ok_or_else(|| FnoxError::ProviderAuthFailed {
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

        // Check the status before decoding: a proxy's 502 page is not JSON, and
        // the status is the useful part of that failure.
        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            let body: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
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

        let body: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: "The token endpoint did not return JSON".to_string(),
                url: URL.to_string(),
            })?;
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
        let expires_at =
            chrono::Utc::now() + chrono::Duration::seconds(ttl.as_secs().min(MAX_TTL_SECS) as i64);

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
        // Revocation was requested, so a missing token must not look like success:
        // the caller would mark the lease revoked while the token stays valid.
        let Some(token) = credentials.and_then(|creds| creds.get(&self.env_var)) else {
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: "The access token is not cached, so it cannot be revoked".to_string(),
                hint: "The token was never cached, or the encryption provider that holds it is unavailable. It expires on its own."
                    .to_string(),
                url: URL.to_string(),
            });
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

    fn backend(
        token_url: &str,
        revocation_url: Option<&str>,
    ) -> Result<Oauth2ClientCredentialsBackend> {
        Oauth2ClientCredentialsBackend::new(
            token_url.to_string(),
            "cid".to_string(),
            None,
            None,
            "OAUTH2_ACCESS_TOKEN".to_string(),
            ClientAuthMethod::Basic,
            IndexMap::new(),
            revocation_url.map(str::to_string),
        )
    }

    #[test]
    fn rejects_cleartext_endpoints_except_on_loopback() {
        assert!(backend("http://idp.example.com/token", None).is_err());
        assert!(
            backend(
                "https://idp.example.com/token",
                Some("http://idp.example.com/revoke")
            )
            .is_err()
        );
        assert!(
            backend(
                "https://idp.example.com/token",
                Some("https://idp.example.com/revoke")
            )
            .is_ok()
        );
        assert!(backend("http://127.0.0.1:8080/token", None).is_ok());
    }

    #[tokio::test]
    async fn revoke_fails_when_the_token_is_not_cached() {
        let with_endpoint = backend(
            "https://idp.example.com/token",
            Some("https://idp.example.com/revoke"),
        )
        .unwrap();
        assert!(with_endpoint.revoke_lease("id", None).await.is_err());

        // Without a revocation endpoint there is nothing to do remotely.
        let without = backend("https://idp.example.com/token", None).unwrap();
        assert!(without.revoke_lease("id", None).await.is_ok());
    }

    #[test]
    fn defaults_to_basic_client_auth() {
        assert_eq!(ClientAuthMethod::default(), ClientAuthMethod::Basic);
    }
}
