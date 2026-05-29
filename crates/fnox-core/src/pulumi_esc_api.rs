//! Shared Pulumi ESC REST API client used by both the lease backend and the
//! secret provider. Handles credential discovery (matching the `esc` CLI) and
//! the `open`/`read` two-step flow for `/api/esc/environments/{ref}/open`.

use crate::env;
use crate::error::{FnoxError, Result};
use indexmap::IndexMap;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

pub const PROVIDER_NAME: &str = "Pulumi ESC";
pub const DEFAULT_API_BASE: &str = "https://api.pulumi.com";

/// Resolved Pulumi Cloud auth: the API base URL plus the bearer token.
/// `base` is the credentials.json `current` account key (a URL on Pulumi Cloud)
/// or `PULUMI_BACKEND_URL`, so self-hosted backends resolve correctly.
pub struct EscAuth {
    pub base: String,
    pub token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PulumiCredentials {
    current: Option<String>,
    #[serde(default)]
    access_tokens: IndexMap<String, String>,
    #[serde(default)]
    accounts: IndexMap<String, PulumiAccount>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PulumiAccount {
    access_token: Option<String>,
}

fn pulumi_home() -> Option<PathBuf> {
    std::env::var("PULUMI_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".pulumi")))
}

/// Sync credential resolver mirroring the `esc` CLI:
/// `FNOX_PULUMI_ACCESS_TOKEN`/`PULUMI_ACCESS_TOKEN` env var →
/// `$PULUMI_HOME/credentials.json` → `~/.pulumi/credentials.json`.
/// Returns an [`EscAuth`] so self-hosted Pulumi Cloud works: the file's
/// `current` field dictates the API base; the env-var path honors
/// `PULUMI_BACKEND_URL` (default `https://api.pulumi.com`).
pub fn resolve_auth() -> std::result::Result<EscAuth, String> {
    if let Ok(token) =
        env::var("FNOX_PULUMI_ACCESS_TOKEN").or_else(|_| env::var("PULUMI_ACCESS_TOKEN"))
    {
        let base =
            std::env::var("PULUMI_BACKEND_URL").unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
        return Ok(EscAuth { base, token });
    }
    let home = pulumi_home().ok_or_else(|| "Could not locate Pulumi home directory".to_string())?;
    let cred_path = home.join("credentials.json");
    let raw = std::fs::read_to_string(&cred_path).map_err(|_| {
        "Pulumi ESC credentials not found. Run 'esc login' or set PULUMI_ACCESS_TOKEN.".to_string()
    })?;
    let creds: PulumiCredentials = serde_json::from_str(&raw)
        .map_err(|e| format!("Failed to parse {}: {e}", cred_path.display()))?;
    let current = creds.current.ok_or_else(|| {
        format!(
            "{} missing 'current' field. Run 'esc login'.",
            cred_path.display()
        )
    })?;
    let token = creds
        .accounts
        .get(&current)
        .and_then(|a| a.access_token.clone())
        .or_else(|| creds.access_tokens.get(&current).cloned())
        .ok_or_else(|| {
            format!(
                "No access token for '{current}' in {}. Run 'esc login'.",
                cred_path.display()
            )
        })?;
    Ok(EscAuth {
        base: current,
        token,
    })
}

/// Resolve auth honoring an optional config-supplied token, producing a
/// `FnoxError` tagged with the caller's help URL on failure.
pub fn resolve_auth_for(config_token: Option<&str>, help_url: &str) -> Result<EscAuth> {
    if let Some(t) = config_token {
        let base =
            std::env::var("PULUMI_BACKEND_URL").unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
        return Ok(EscAuth {
            base,
            token: t.to_string(),
        });
    }
    resolve_auth().map_err(|details| FnoxError::ProviderAuthFailed {
        provider: PROVIDER_NAME.to_string(),
        details,
        hint: "Run 'esc login' or set PULUMI_ACCESS_TOKEN".to_string(),
        url: help_url.to_string(),
    })
}

/// `org/project/env` (modern) or `org/env` (legacy, no project). Each segment
/// is percent-encoded so names containing URL-special chars (`/`, `?`, `#`,
/// whitespace) can't corrupt the request path. Pulumi Cloud names are typically
/// `[a-zA-Z0-9-]`, but encoding is cheap insurance.
pub fn build_env_ref(organization: &str, project: Option<&str>, environment: &str) -> String {
    let org = urlencoding::encode(organization);
    let env = urlencoding::encode(environment);
    match project {
        Some(p) => format!("{org}/{}/{env}", urlencoding::encode(p)),
        None => format!("{org}/{env}"),
    }
}

/// Coerce a `{value, trace}`-wrapped ESC node to its string form. The inner
/// `.value` is usually a string, but ESC passes booleans and numbers through
/// verbatim — coerce those to their JSON-string form so callers can always
/// export them as env vars.
pub fn coerce_scalar(wrapped: &serde_json::Value) -> Option<String> {
    match wrapped.get("value")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Walk the resolved `properties` tree for a dot-path like `anthropic.api_key`.
/// Every node is wrapped in `{value, trace}`, so we unwrap `.value` to descend
/// into each intermediate segment, then `coerce_scalar` the final node.
pub fn lookup(root: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = root.pointer("/properties")?;
    let mut segments = path.split('.').peekable();
    while let Some(segment) = segments.next() {
        cur = cur.get(segment)?;
        if segments.peek().is_some() {
            cur = cur.get("value")?;
        }
    }
    coerce_scalar(cur)
}

#[derive(Deserialize)]
struct OpenResponse {
    id: String,
}

/// HTTP client bound to one (base_url, token, help_url) context.
pub struct EscClient {
    base: String,
    auth: String,
    help_url: String,
    http: reqwest::Client,
}

impl EscClient {
    /// Construct a client, resolving auth via `resolve_auth_for`.
    pub fn new(config_token: Option<&str>, help_url: &str) -> Result<Self> {
        let EscAuth { base, token } = resolve_auth_for(config_token, help_url)?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            auth: format!("token {token}"),
            help_url: help_url.to_string(),
            http: crate::http::http_client(),
        })
    }

    /// Build a `ProviderApiError` tagged with this client's provider name and help URL.
    fn api_err(&self, details: impl Into<String>, hint: &str) -> FnoxError {
        FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details: details.into(),
            hint: hint.to_string(),
            url: self.help_url.clone(),
        }
    }

    /// Build a `ProviderInvalidResponse` tagged with this client's provider name and help URL.
    fn invalid_err(&self, details: impl Into<String>, hint: &str) -> FnoxError {
        FnoxError::ProviderInvalidResponse {
            provider: PROVIDER_NAME.to_string(),
            details: details.into(),
            hint: hint.to_string(),
            url: self.help_url.clone(),
        }
    }

    async fn http_error(&self, resp: reqwest::Response) -> FnoxError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let details = format!("HTTP {status}: {body}");
        if status.as_u16() == 401 || status.as_u16() == 403 {
            FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details,
                hint: "Run 'esc login' or check PULUMI_ACCESS_TOKEN".to_string(),
                url: self.help_url.clone(),
            }
        } else {
            self.api_err(
                details,
                "Check organization/project/environment in your config",
            )
        }
    }

    /// `POST /api/esc/environments/{env_ref}/open?duration=...` → session id.
    pub async fn open(&self, env_ref: &str, duration: Duration) -> Result<String> {
        let url = format!("{}/api/esc/environments/{env_ref}/open", self.base);
        let duration_param = format!("{}s", duration.as_secs());
        let resp = self
            .http
            .post(&url)
            .header("Authorization", &self.auth)
            .query(&[("duration", duration_param.as_str())])
            .send()
            .await
            .map_err(|e| self.api_err(e.to_string(), "Failed to reach Pulumi Cloud"))?;
        if !resp.status().is_success() {
            return Err(self.http_error(resp).await);
        }
        let open: OpenResponse = resp.json().await.map_err(|e| {
            self.invalid_err(
                format!("Failed to parse open response: {e}"),
                "Unexpected response from Pulumi ESC 'open' endpoint",
            )
        })?;
        Ok(open.id)
    }

    /// `GET /api/esc/environments/{env_ref}/open/{session_id}` → full resolved env.
    pub async fn read(&self, env_ref: &str, session_id: &str) -> Result<serde_json::Value> {
        let url = format!(
            "{}/api/esc/environments/{env_ref}/open/{session_id}",
            self.base
        );
        let resp = self
            .http
            .get(&url)
            .header("Authorization", &self.auth)
            .send()
            .await
            .map_err(|e| self.api_err(e.to_string(), "Failed to read opened ESC environment"))?;
        if !resp.status().is_success() {
            return Err(self.http_error(resp).await);
        }
        resp.json().await.map_err(|e| {
            self.invalid_err(
                format!("Failed to parse environment response: {e}"),
                "Unexpected response from Pulumi ESC",
            )
        })
    }

    /// Open + read as one call. Good for batch reads where you want the full tree.
    pub async fn open_and_read(
        &self,
        env_ref: &str,
        duration: Duration,
    ) -> Result<serde_json::Value> {
        let id = self.open(env_ref, duration).await?;
        self.read(env_ref, &id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ref_with_project() {
        assert_eq!(build_env_ref("org", Some("proj"), "env"), "org/proj/env");
    }

    #[test]
    fn env_ref_without_project() {
        assert_eq!(build_env_ref("org", None, "env"), "org/env");
    }

    fn sample_body() -> serde_json::Value {
        serde_json::json!({
            "properties": {
                "anthropic": {
                    "value": { "api_key": { "value": "sk-test-123" } }
                },
                "aws": {
                    "value": {
                        "region": { "value": "us-west-2" },
                        "port": { "value": 5432 }
                    }
                }
            }
        })
    }

    #[test]
    fn coerce_scalar_handles_scalar_types() {
        assert_eq!(
            coerce_scalar(&serde_json::json!({"value": "hello", "trace": {}})),
            Some("hello".to_string())
        );
        assert_eq!(
            coerce_scalar(&serde_json::json!({"value": false})),
            Some("false".to_string())
        );
        assert_eq!(
            coerce_scalar(&serde_json::json!({"value": 42})),
            Some("42".to_string())
        );
        assert_eq!(coerce_scalar(&serde_json::json!({"value": null})), None);
        assert_eq!(coerce_scalar(&serde_json::json!({"trace": {}})), None);
    }

    #[test]
    fn build_env_ref_percent_encodes_segments() {
        assert_eq!(
            build_env_ref("my/org", Some("a b"), "dev#1"),
            "my%2Forg/a%20b/dev%231"
        );
    }

    #[test]
    fn lookup_walks_value_wrappers() {
        let b = sample_body();
        assert_eq!(lookup(&b, "anthropic.api_key"), Some("sk-test-123".into()));
        assert_eq!(lookup(&b, "aws.region"), Some("us-west-2".into()));
        assert_eq!(lookup(&b, "aws.port"), Some("5432".into()));
        assert_eq!(lookup(&b, "nope"), None);
    }

    #[test]
    fn parse_credentials_prefers_accounts_access_token() {
        let json = r#"{
            "current": "https://api.pulumi.com",
            "accessTokens": {"https://api.pulumi.com": "fallback"},
            "accounts": {"https://api.pulumi.com": {"accessToken": "primary"}}
        }"#;
        let creds: PulumiCredentials = serde_json::from_str(json).unwrap();
        let current = creds.current.unwrap();
        let acct_tok = creds
            .accounts
            .get(&current)
            .and_then(|a| a.access_token.clone());
        assert_eq!(acct_tok.as_deref(), Some("primary"));
    }
}
