use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;

use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/github-app";
const API_BASE: &str = "https://api.github.com";

/// Maximum GitHub installation token lifetime (1 hour)
const MAX_DURATION_SECS: u64 = 3600;

/// JWT expiration — GitHub accepts up to 10 minutes
const JWT_EXPIRY_SECS: i64 = 600;

pub fn check_prerequisites(private_key_file: &Option<String>) -> Option<String> {
    let has_key = std::env::var("FNOX_GITHUB_APP_PRIVATE_KEY").is_ok()
        || private_key_file
            .as_ref()
            .is_some_and(|f| std::path::Path::new(&shellexpand::tilde(f).into_owned()).exists());
    if has_key {
        None
    } else {
        Some(
            "GitHub App private key not found. Set FNOX_GITHUB_APP_PRIVATE_KEY \
             or configure private_key_file pointing to a PEM file."
                .to_string(),
        )
    }
}

pub fn required_env_vars() -> Vec<(&'static str, &'static str)> {
    // The env var is optional when private_key_file is configured, so we
    // don't unconditionally list it as required. check_prerequisites()
    // handles the two-path validation correctly.
    vec![]
}

pub struct GitHubAppBackend {
    app_id: String,
    installation_id: String,
    private_key_file: Option<String>,
    env_var: String,
    permissions: Option<IndexMap<String, String>>,
    repositories: Option<Vec<String>>,
    api_base: Option<String>,
}

impl GitHubAppBackend {
    pub fn new(
        app_id: String,
        installation_id: String,
        private_key_file: Option<String>,
        env_var: String,
        permissions: Option<IndexMap<String, String>>,
        repositories: Option<Vec<String>>,
        api_base: Option<String>,
    ) -> Self {
        Self {
            app_id,
            installation_id,
            private_key_file,
            env_var,
            permissions,
            repositories,
            api_base,
        }
    }

    fn api_base(&self) -> &str {
        self.api_base.as_deref().unwrap_or(API_BASE)
    }

    fn load_private_key(&self) -> Result<String> {
        // Prefer env var
        if let Ok(key) = std::env::var("FNOX_GITHUB_APP_PRIVATE_KEY") {
            return Ok(key);
        }

        // Fall back to file
        if let Some(ref path) = self.private_key_file {
            let expanded = shellexpand::tilde(path).into_owned();
            std::fs::read_to_string(&expanded).map_err(|e| FnoxError::ProviderAuthFailed {
                provider: "GitHub App".to_string(),
                details: format!("Failed to read private key from {expanded}: {e}"),
                hint: "Check that private_key_file points to a valid PEM file".to_string(),
                url: URL.to_string(),
            })
        } else {
            Err(FnoxError::ProviderAuthFailed {
                provider: "GitHub App".to_string(),
                details: "No private key available".to_string(),
                hint: "Set FNOX_GITHUB_APP_PRIVATE_KEY or configure private_key_file".to_string(),
                url: URL.to_string(),
            })
        }
    }

    /// Generate a JWT for authenticating as the GitHub App.
    fn generate_jwt(&self, pem_key: &str) -> Result<String> {
        let now = chrono::Utc::now();
        let iat = now.timestamp() - 60; // issued 60s in the past to allow clock drift
        let exp = iat + JWT_EXPIRY_SECS; // exp - iat must be ≤ 600s (GitHub's limit)

        let app_id_num: u64 = self
            .app_id
            .parse()
            .map_err(|_| FnoxError::ProviderAuthFailed {
                provider: "GitHub App".to_string(),
                details: format!("app_id '{}' is not a valid integer", self.app_id),
                hint: "app_id must be a numeric GitHub App ID".to_string(),
                url: URL.to_string(),
            })?;

        let claims = serde_json::json!({
            "iat": iat,
            "exp": exp,
            "iss": app_id_num,
        });

        let key = jsonwebtoken::EncodingKey::from_rsa_pem(pem_key.as_bytes()).map_err(|e| {
            FnoxError::ProviderAuthFailed {
                provider: "GitHub App".to_string(),
                details: format!("Invalid RSA private key: {e}"),
                hint: "Check that the private key is a valid RSA PEM file".to_string(),
                url: URL.to_string(),
            }
        })?;

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        jsonwebtoken::encode(&header, &claims, &key).map_err(|e| FnoxError::ProviderAuthFailed {
            provider: "GitHub App".to_string(),
            details: format!("Failed to sign JWT: {e}"),
            hint: "Check the private key format".to_string(),
            url: URL.to_string(),
        })
    }
}

#[async_trait]
impl LeaseBackend for GitHubAppBackend {
    async fn create_lease(&self, _duration: Duration, _label: &str) -> Result<Lease> {
        let pem_key = self.load_private_key()?;
        let jwt = self.generate_jwt(&pem_key)?;
        let api_base = self.api_base();

        let mut body = serde_json::Map::new();
        if let Some(ref permissions) = self.permissions {
            body.insert(
                "permissions".to_string(),
                serde_json::to_value(permissions).unwrap(),
            );
        }
        if let Some(ref repositories) = self.repositories {
            body.insert(
                "repositories".to_string(),
                serde_json::to_value(repositories).unwrap(),
            );
        }

        let client = crate::http::http_client();
        let url = format!(
            "{api_base}/app/installations/{}/access_tokens",
            self.installation_id
        );

        let response = client
            .post(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(&jwt)
            .json(&body)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "GitHub App".to_string(),
                details: e.to_string(),
                hint: "Failed to connect to GitHub API".to_string(),
                url: URL.to_string(),
            })?;

        let status = response.status();
        let resp: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| FnoxError::ProviderInvalidResponse {
                    provider: "GitHub App".to_string(),
                    details: e.to_string(),
                    hint: "Unexpected response from GitHub API".to_string(),
                    url: URL.to_string(),
                })?;

        if !status.is_success() {
            let message = resp["message"]
                .as_str()
                .unwrap_or(&format!("HTTP {status}"))
                .to_string();

            if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "GitHub App".to_string(),
                    details: message,
                    hint: "Check app_id, installation_id, and private key".to_string(),
                    url: URL.to_string(),
                });
            }
            if status.as_u16() == 404 {
                return Err(FnoxError::ProviderApiError {
                    provider: "GitHub App".to_string(),
                    details: message,
                    hint: "Check that the installation_id is correct and the app is installed"
                        .to_string(),
                    url: URL.to_string(),
                });
            }
            if status.as_u16() == 422 {
                return Err(FnoxError::ProviderApiError {
                    provider: "GitHub App".to_string(),
                    details: message,
                    hint: "Check permissions and repositories configuration".to_string(),
                    url: URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderApiError {
                provider: "GitHub App".to_string(),
                details: message,
                hint: "Failed to create installation access token".to_string(),
                url: URL.to_string(),
            });
        }

        let token = resp["token"]
            .as_str()
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "GitHub App".to_string(),
                details: "Response missing 'token' field".to_string(),
                hint: "Unexpected response from GitHub API".to_string(),
                url: URL.to_string(),
            })?;

        let expires_at = resp["expires_at"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        let mut credentials = IndexMap::new();
        credentials.insert(self.env_var.clone(), token.to_string());

        // Use the token itself as the lease_id so revoke_lease can call
        // DELETE /installation/token (which authenticates with the token).
        let lease_id = token.to_string();

        Ok(Lease {
            credentials,
            expires_at,
            lease_id,
        })
    }

    async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        // The lease_id is the installation token itself, so we can authenticate
        // the DELETE /installation/token request with it.
        let api_base = self.api_base();
        let url = format!("{api_base}/installation/token");

        let client = crate::http::http_client();
        let response = client
            .delete(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(lease_id)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "GitHub App".to_string(),
                details: e.to_string(),
                hint: "Failed to connect to GitHub API for token revocation".to_string(),
                url: URL.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            // 404 = token already expired or revoked — treat as success
            if status.as_u16() != 404 {
                let body_text = response.text().await.unwrap_or_default();
                return Err(FnoxError::ProviderApiError {
                    provider: "GitHub App".to_string(),
                    details: format!("HTTP {status}: {body_text}"),
                    hint: "Failed to revoke GitHub installation token".to_string(),
                    url: URL.to_string(),
                });
            }
        }

        Ok(())
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(MAX_DURATION_SECS)
    }
}
