use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/github-oauth";
const PROVIDER: &str = "GitHub OAuth";
const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_TOKEN_SECS: i64 = 8 * 60 * 60;
const CACHE_REUSE_BUFFER_SECS: i64 = 300;

/// All env var names the GitHub OAuth backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = &[];

pub fn check_prerequisites() -> Option<String> {
    None
}

pub fn required_env_vars() -> Vec<(&'static str, &'static str)> {
    vec![]
}

#[derive(Debug, Clone)]
pub struct GitHubOauthBackend {
    client_id: String,
    scope: String,
    env_var: String,
    keyring_service: String,
    keyring_cache: bool,
    open_browser: bool,
    auth_base: String,
    api_base: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    #[serde(default = "default_poll_interval")]
    interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    refresh_token_expires_in: Option<i64>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UserResponse {
    login: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedToken {
    access_token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<String>,
}

impl GitHubOauthBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: String,
        scope: String,
        env_var: String,
        keyring_service: String,
        keyring_cache: bool,
        open_browser: bool,
        auth_base: String,
        api_base: String,
    ) -> Self {
        Self {
            client_id,
            scope,
            env_var,
            keyring_service,
            keyring_cache,
            open_browser,
            auth_base,
            api_base,
        }
    }

    fn cache_key(&self) -> String {
        let hash = blake3::hash(
            format!(
                "{}|{}|{}|{}",
                self.client_id, self.scope, self.auth_base, self.api_base
            )
            .as_bytes(),
        );
        format!("{}-{}", self.client_id, &hash.to_hex()[..16])
    }

    fn keyring_entry(&self) -> Result<Entry> {
        Entry::new(&self.keyring_service, &self.cache_key()).map_err(|e| {
            FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Failed to create keyring entry: {e}"),
                hint: "Check that the OS keyring is available, or set keyring_cache = false"
                    .to_string(),
                url: URL.to_string(),
            }
        })
    }

    fn read_cached_token(&self) -> Option<CachedToken> {
        if !self.keyring_cache {
            return None;
        }
        let entry = self.keyring_entry().ok()?;
        let value = entry.get_password().ok()?;
        serde_json::from_str(&value).ok()
    }

    fn write_cached_token(&self, token: &CachedToken) {
        if !self.keyring_cache {
            return;
        }
        let Ok(entry) = self.keyring_entry() else {
            return;
        };
        let Ok(value) = serde_json::to_string(token) else {
            return;
        };
        if let Err(e) = entry.set_password(&value) {
            tracing::warn!("Failed to cache GitHub OAuth token in keyring: {e}");
        }
    }

    async fn create_device_code(&self) -> Result<DeviceCodeResponse> {
        let url = format!("{}/device/code", self.device_auth_base());
        crate::http::http_client()
            .post(url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("scope", self.scope.as_str()),
            ])
            .send()
            .await
            .map_err(|e| api_error(format!("Failed to request device code: {e}")))?
            .json::<DeviceCodeResponse>()
            .await
            .map_err(|e| invalid_response(format!("Invalid device code response: {e}")))
    }

    fn device_auth_base(&self) -> &str {
        self.auth_base
            .trim_end_matches('/')
            .strip_suffix("/oauth")
            .unwrap_or_else(|| self.auth_base.trim_end_matches('/'))
    }

    async fn poll_access_token(&self, device: &DeviceCodeResponse) -> Result<TokenResponse> {
        let deadline = chrono::Utc::now() + chrono::Duration::seconds(device.expires_in as i64);
        let mut interval = device.interval.max(1);
        let url = format!("{}/access_token", self.auth_base.trim_end_matches('/'));

        loop {
            if chrono::Utc::now() >= deadline {
                return Err(auth_failed("Device authorization expired".to_string()));
            }

            let response = crate::http::http_client()
                .post(&url)
                .header("Accept", "application/json")
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("device_code", device.device_code.as_str()),
                    ("grant_type", GRANT_DEVICE_CODE),
                ])
                .send()
                .await
                .map_err(|e| api_error(format!("Failed to poll access token: {e}")))?
                .json::<TokenResponse>()
                .await
                .map_err(|e| invalid_response(format!("Invalid token response: {e}")))?;

            match response.error.as_deref() {
                None => return Ok(response),
                Some("authorization_pending") => {
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                    continue;
                }
                Some("slow_down") => {
                    interval += 5;
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                    continue;
                }
                Some("expired_token") => {
                    return Err(auth_failed("Device authorization expired".to_string()));
                }
                Some("access_denied") => {
                    return Err(auth_failed("Device authorization was denied".to_string()));
                }
                Some(error) => {
                    let details = response
                        .error_description
                        .unwrap_or_else(|| error.to_string());
                    return Err(api_error(details));
                }
            }
        }
    }

    async fn refresh_access_token(&self, cached: &CachedToken) -> Result<Option<CachedToken>> {
        let Some(refresh_token) = cached.refresh_token.as_deref() else {
            return Ok(None);
        };
        if cached
            .refresh_expires_at
            .is_some_and(|exp| exp <= chrono::Utc::now())
        {
            return Ok(None);
        }

        let url = format!("{}/access_token", self.auth_base.trim_end_matches('/'));
        let response = crate::http::http_client()
            .post(url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .map_err(|e| api_error(format!("Failed to refresh access token: {e}")))?
            .json::<TokenResponse>()
            .await
            .map_err(|e| invalid_response(format!("Invalid refresh response: {e}")))?;

        if let Some(err) = &response.error {
            tracing::debug!(
                error = err.as_str(),
                description = response.error_description.as_deref().unwrap_or(""),
                "GitHub OAuth refresh token rejected; falling back to device flow"
            );
            return Ok(None);
        }

        let mut refreshed = self
            .token_response_to_cache(response, cached.login.clone())
            .await?;
        if refreshed.login.is_none() {
            refreshed.login = cached.login.clone();
        }
        Ok(Some(refreshed))
    }

    async fn token_response_to_cache(
        &self,
        response: TokenResponse,
        login: Option<String>,
    ) -> Result<CachedToken> {
        let access_token = response.access_token.ok_or_else(|| {
            invalid_response("Token response missing 'access_token' field".to_string())
        })?;
        let now = chrono::Utc::now();
        let expires_at =
            now + chrono::Duration::seconds(response.expires_in.unwrap_or(DEFAULT_TOKEN_SECS));
        let refresh_expires_at = response
            .refresh_token_expires_in
            .map(|secs| now + chrono::Duration::seconds(secs));
        let login = match login {
            Some(login) => Some(login),
            None => self.get_login(&access_token).await.ok(),
        };

        Ok(CachedToken {
            access_token,
            expires_at,
            refresh_token: response.refresh_token,
            refresh_expires_at,
            login,
        })
    }

    async fn get_login(&self, access_token: &str) -> Result<String> {
        let url = format!("{}/user", self.api_base.trim_end_matches('/'));
        let response = crate::http::http_client()
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| api_error(format!("Failed to fetch authenticated GitHub user: {e}")))?
            .json::<UserResponse>()
            .await
            .map_err(|e| invalid_response(format!("Invalid GitHub user response: {e}")))?;
        response.login.ok_or_else(|| {
            invalid_response(
                response
                    .message
                    .unwrap_or_else(|| "Response missing 'login' field".to_string()),
            )
        })
    }

    fn print_device_instructions(&self, device: &DeviceCodeResponse) {
        eprintln!(
            "Open {} and enter code {} to authorize GitHub access.",
            device.verification_uri, device.user_code
        );
        if self.open_browser {
            let url = device.verification_uri.clone();
            std::mem::drop(tokio::task::spawn_blocking(move || {
                let _ = open_browser(&url);
            }));
        }
    }

    async fn create_or_load_token(&self) -> Result<CachedToken> {
        if let Some(cached) = self.read_cached_token() {
            let buffer = chrono::Duration::seconds(CACHE_REUSE_BUFFER_SECS);
            if cached.expires_at - buffer > chrono::Utc::now() {
                return Ok(cached);
            }
            if let Some(refreshed) = self.refresh_access_token(&cached).await? {
                self.write_cached_token(&refreshed);
                return Ok(refreshed);
            }
        }

        let device = self.create_device_code().await?;
        self.print_device_instructions(&device);
        let response = self.poll_access_token(&device).await?;
        let token = self.token_response_to_cache(response, None).await?;
        self.write_cached_token(&token);
        Ok(token)
    }
}

#[async_trait]
impl LeaseBackend for GitHubOauthBackend {
    async fn create_lease(&self, _duration: Duration, _label: &str) -> Result<Lease> {
        let token = self.create_or_load_token().await?;

        let mut credentials = IndexMap::new();
        credentials.insert(self.env_var.clone(), token.access_token.clone());

        Ok(Lease {
            credentials,
            expires_at: Some(token.expires_at),
            lease_id: super::generate_lease_id("github-oauth"),
        })
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(DEFAULT_TOKEN_SECS as u64)
    }
}

fn default_poll_interval() -> u64 {
    5
}

fn invalid_response(details: String) -> FnoxError {
    FnoxError::ProviderInvalidResponse {
        provider: PROVIDER.to_string(),
        details,
        hint: "Unexpected response from GitHub OAuth API".to_string(),
        url: URL.to_string(),
    }
}

fn api_error(details: String) -> FnoxError {
    FnoxError::ProviderApiError {
        provider: PROVIDER.to_string(),
        details,
        hint: "Failed to create GitHub user access token".to_string(),
        url: URL.to_string(),
    }
}

fn auth_failed(details: String) -> FnoxError {
    FnoxError::ProviderAuthFailed {
        provider: PROVIDER.to_string(),
        details,
        hint: "Run the command again and approve the device authorization prompt".to_string(),
        url: URL.to_string(),
    }
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).status()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(url).status()?;
    }
    Ok(())
}
