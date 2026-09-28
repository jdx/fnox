//! Shared Pulumi ESC REST API client used by both the lease backend and the
//! secret provider. Handles credential discovery (matching the `esc` CLI) and
//! the `open`/`read` two-step flow for `/api/esc/environments/{ref}/open`.

use crate::env;
use crate::error::{FnoxError, Result};
use indexmap::IndexMap;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::path::PathBuf;
use std::time::Duration;

pub const PROVIDER_NAME: &str = "Pulumi ESC";
pub const DEFAULT_API_BASE: &str = "https://api.pulumi.com";
/// Project the `esc` CLI uses for environments addressed as `org/env`.
pub const DEFAULT_PROJECT: &str = "default";
pub const ENV_VARS: &[&str] = &[
    "PULUMI_ACCESS_TOKEN",
    "FNOX_PULUMI_ACCESS_TOKEN",
    "PULUMI_BACKEND_URL",
    "PULUMI_HOME",
];

const AUTH_HINT: &str = "Run 'esc login' or set PULUMI_ACCESS_TOKEN";

struct EscAuth {
    base: String,
    token: String,
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
    env::var("PULUMI_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".pulumi")))
}

/// `PULUMI_BACKEND_URL` wins over the credentials file's `current`, as in the
/// Pulumi CLI. Only HTTP(S) URLs are Pulumi Cloud; DIY state backends
/// (`s3://`, `file://`, ...) fall through to the default cloud.
fn api_base(backend_url: Option<String>, current: Option<String>) -> String {
    [backend_url, current]
        .into_iter()
        .flatten()
        .find(|u| u.starts_with("https://") || u.starts_with("http://"))
        .unwrap_or_else(|| DEFAULT_API_BASE.to_string())
}

fn token_for(creds: &PulumiCredentials, base: &str) -> Option<String> {
    creds
        .accounts
        .get(base)
        .and_then(|a| a.access_token.clone())
        .or_else(|| creds.access_tokens.get(base).cloned())
}

/// Token order mirrors the `esc` CLI: config `token` →
/// `FNOX_PULUMI_ACCESS_TOKEN`/`PULUMI_ACCESS_TOKEN` →
/// `$PULUMI_HOME/credentials.json` (default `~/.pulumi/credentials.json`).
pub fn resolve_auth(config_token: Option<&str>, help_url: &str) -> Result<()> {
    resolve(config_token, help_url).map(|_| ())
}

fn resolve(config_token: Option<&str>, help_url: &str) -> Result<EscAuth> {
    let auth_err = |details: String| FnoxError::ProviderAuthFailed {
        provider: PROVIDER_NAME.to_string(),
        details,
        hint: AUTH_HINT.to_string(),
        url: help_url.to_string(),
    };
    let backend_url = env::var("PULUMI_BACKEND_URL").ok();
    let env_token = config_token.map(str::to_string).or_else(|| {
        env::var("FNOX_PULUMI_ACCESS_TOKEN")
            .or_else(|_| env::var("PULUMI_ACCESS_TOKEN"))
            .ok()
    });
    if let Some(token) = env_token {
        return Ok(EscAuth {
            base: api_base(backend_url, None),
            token,
        });
    }
    let home =
        pulumi_home().ok_or_else(|| auth_err("Could not locate Pulumi home directory".into()))?;
    let cred_path = home.join("credentials.json");
    let raw = std::fs::read_to_string(&cred_path).map_err(|e| {
        auth_err(match e.kind() {
            std::io::ErrorKind::NotFound => "Pulumi ESC credentials not found".to_string(),
            _ => format!("Failed to read {}: {e}", cred_path.display()),
        })
    })?;
    let creds: PulumiCredentials = serde_json::from_str(&raw)
        .map_err(|e| auth_err(format!("Failed to parse {}: {e}", cred_path.display())))?;
    let base = api_base(backend_url, creds.current.clone());
    let token = token_for(&creds, &base).ok_or_else(|| {
        auth_err(format!(
            "No access token for '{base}' in {}",
            cred_path.display()
        ))
    })?;
    Ok(EscAuth { base, token })
}

/// Names come from Pulumi Cloud and are typically `[a-zA-Z0-9-]`, but each
/// segment is percent-encoded so a stray `/` or `#` can't reshape the path.
pub fn build_env_ref(organization: &str, project: Option<&str>, environment: &str) -> String {
    format!(
        "{}/{}/{}",
        urlencoding::encode(organization),
        urlencoding::encode(project.unwrap_or(DEFAULT_PROJECT)),
        urlencoding::encode(environment)
    )
}

pub fn invalid_response(details: impl Into<String>, hint: &str, help_url: &str) -> FnoxError {
    FnoxError::ProviderInvalidResponse {
        provider: PROVIDER_NAME.to_string(),
        details: details.into(),
        hint: hint.to_string(),
        url: help_url.to_string(),
    }
}

/// Unwrap a `{value, trace}` ESC node to a string. Booleans and numbers are
/// coerced so callers can always export them as env vars.
pub fn coerce_scalar(wrapped: &serde_json::Value) -> Option<String> {
    match wrapped.get("value")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Every node under `properties` is wrapped in `{value, trace}`; numeric
/// segments index into arrays.
fn find<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = root.get("properties")?;
    for (i, segment) in path.split('.').enumerate() {
        if i > 0 {
            cur = cur.get("value")?;
        }
        cur = match cur {
            serde_json::Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => cur.get(segment)?,
        };
    }
    Some(cur)
}

/// Resolve a dot-path like `db.url` or `hosts.0` to its scalar value.
pub fn lookup(root: &serde_json::Value, path: &str, help_url: &str) -> Result<String> {
    let node = find(root, path).ok_or_else(|| FnoxError::ProviderSecretNotFound {
        provider: PROVIDER_NAME.to_string(),
        secret: path.to_string(),
        hint: "Check that the path exists in your Pulumi ESC environment".to_string(),
        url: help_url.to_string(),
    })?;
    coerce_scalar(node).ok_or_else(|| {
        invalid_response(
            format!("'{path}' is not a string, number, or boolean"),
            "Point the path at a scalar leaf, not an object or array",
            help_url,
        )
    })
}

/// One ESC environment, plus an optional config-supplied token.
pub struct EscEnv {
    pub organization: String,
    pub project: Option<String>,
    pub environment: String,
    pub token: Option<String>,
}

#[derive(Deserialize)]
struct OpenResponse {
    id: String,
}

impl EscEnv {
    pub fn env_ref(&self) -> String {
        build_env_ref(
            &self.organization,
            self.project.as_deref(),
            &self.environment,
        )
    }

    /// `POST .../open?duration=` then `GET .../open/{id}` → fully resolved env.
    pub async fn open(&self, duration: Duration, help_url: &str) -> Result<serde_json::Value> {
        let EscAuth { base, token } = resolve(self.token.as_deref(), help_url)?;
        let client = EscClient {
            auth: format!("token {token}"),
            help_url,
            http: crate::http::http_client(),
        };
        let url = format!(
            "{}/api/esc/environments/{}/open",
            base.trim_end_matches('/'),
            self.env_ref()
        );
        let duration = format!("{}s", duration.as_secs());
        let open: OpenResponse = client
            .send_json(
                client.http.post(&url).query(&[("duration", duration)]),
                "open",
            )
            .await?;
        client
            .send_json(client.http.get(format!("{url}/{}", open.id)), "read")
            .await
    }
}

struct EscClient<'a> {
    auth: String,
    help_url: &'a str,
    http: reqwest::Client,
}

impl EscClient<'_> {
    async fn send_json<T: DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
        step: &str,
    ) -> Result<T> {
        let resp = req
            .header("Authorization", &self.auth)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: e.to_string(),
                hint: "Failed to reach Pulumi Cloud".to_string(),
                url: self.help_url.to_string(),
            })?;
        let status = resp.status();
        if !status.is_success() {
            let details = format!("HTTP {status}: {}", resp.text().await.unwrap_or_default());
            return Err(match status.as_u16() {
                401 | 403 => FnoxError::ProviderAuthFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details,
                    hint: AUTH_HINT.to_string(),
                    url: self.help_url.to_string(),
                },
                _ => FnoxError::ProviderApiError {
                    provider: PROVIDER_NAME.to_string(),
                    details,
                    hint: "Check organization/project/environment in your config".to_string(),
                    url: self.help_url.to_string(),
                },
            });
        }
        resp.json().await.map_err(|e| {
            invalid_response(
                format!("Failed to parse ESC {step} response: {e}"),
                "Unexpected response from Pulumi ESC",
                self.help_url,
            )
        })
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
    fn env_ref_without_project_uses_default_project() {
        assert_eq!(build_env_ref("org", None, "env"), "org/default/env");
    }

    #[test]
    fn build_env_ref_percent_encodes_segments() {
        assert_eq!(
            build_env_ref("my/org", Some("a b"), "dev#1"),
            "my%2Forg/a%20b/dev%231"
        );
    }

    #[test]
    fn api_base_prefers_backend_url_and_skips_non_http() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(api_base(None, None), DEFAULT_API_BASE);
        assert_eq!(
            api_base(s("https://esc.corp"), s("https://api.pulumi.com")),
            "https://esc.corp"
        );
        assert_eq!(
            api_base(s("s3://bucket"), s("https://esc.corp")),
            "https://esc.corp"
        );
        assert_eq!(api_base(None, s("file://~")), DEFAULT_API_BASE);
    }

    #[test]
    fn token_for_prefers_accounts_then_access_tokens() {
        let creds: PulumiCredentials = serde_json::from_str(
            r#"{
                "accessTokens": {"https://a": "fallback", "https://b": "only-legacy"},
                "accounts": {"https://a": {"accessToken": "primary"}}
            }"#,
        )
        .unwrap();
        assert_eq!(token_for(&creds, "https://a").as_deref(), Some("primary"));
        assert_eq!(
            token_for(&creds, "https://b").as_deref(),
            Some("only-legacy")
        );
        assert_eq!(token_for(&creds, "https://c"), None);
    }

    #[test]
    fn coerce_scalar_handles_scalar_types() {
        let c = |v| coerce_scalar(&v);
        assert_eq!(
            c(serde_json::json!({"value": "hello", "trace": {}})),
            Some("hello".into())
        );
        assert_eq!(c(serde_json::json!({"value": false})), Some("false".into()));
        assert_eq!(c(serde_json::json!({"value": 42})), Some("42".into()));
        assert_eq!(c(serde_json::json!({"value": null})), None);
        assert_eq!(c(serde_json::json!({"trace": {}})), None);
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
                },
                "hosts": {
                    "value": [ { "value": "a.example" }, { "value": "b.example" } ]
                }
            }
        })
    }

    #[test]
    fn lookup_walks_value_wrappers_and_arrays() {
        let b = sample_body();
        let l = |p| lookup(&b, p, "u");
        assert_eq!(l("anthropic.api_key").unwrap(), "sk-test-123");
        assert_eq!(l("aws.port").unwrap(), "5432");
        assert_eq!(l("hosts.1").unwrap(), "b.example");
        assert!(matches!(
            l("nope"),
            Err(FnoxError::ProviderSecretNotFound { .. })
        ));
        assert!(matches!(
            l("hosts.9"),
            Err(FnoxError::ProviderSecretNotFound { .. })
        ));
        assert!(matches!(
            l("aws"),
            Err(FnoxError::ProviderInvalidResponse { .. })
        ));
    }
}
