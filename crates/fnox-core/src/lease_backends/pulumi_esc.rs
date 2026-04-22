use crate::env;
use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/pulumi-esc";
const DEFAULT_API_BASE: &str = "https://api.pulumi.com";

pub const CONSUMED_ENV_VARS: &[&str] = &[
    "PULUMI_ACCESS_TOKEN",
    "FNOX_PULUMI_ACCESS_TOKEN",
    "PULUMI_BACKEND_URL",
    "PULUMI_HOME",
];

pub fn check_prerequisites() -> Option<String> {
    resolve_auth().err()
}

pub fn required_env_vars() -> Vec<(&'static str, &'static str)> {
    vec![("PULUMI_ACCESS_TOKEN", "Pulumi Cloud access token")]
}

fn pulumi_home() -> Option<PathBuf> {
    std::env::var("PULUMI_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".pulumi")))
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

/// Resolve (base_url, token) the same way the `esc` CLI does:
/// env var → $PULUMI_HOME/credentials.json → ~/.pulumi/credentials.json.
fn resolve_auth() -> std::result::Result<(String, String), String> {
    if let Ok(token) =
        env::var("FNOX_PULUMI_ACCESS_TOKEN").or_else(|_| env::var("PULUMI_ACCESS_TOKEN"))
    {
        let base =
            std::env::var("PULUMI_BACKEND_URL").unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
        return Ok((base, token));
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
    Ok((current, token))
}

pub struct PulumiEscBackend {
    organization: String,
    project: Option<String>,
    environment: String,
    token: Option<String>,
    env_vars: Option<Vec<String>>,
    interpolate: Option<char>,
}

impl PulumiEscBackend {
    pub fn new(
        organization: String,
        project: Option<String>,
        environment: String,
        token: Option<String>,
        env_vars: Option<Vec<String>>,
        interpolate: Option<char>,
    ) -> Self {
        Self {
            organization,
            project,
            environment,
            token,
            env_vars,
            interpolate,
        }
    }

    fn env_ref(&self) -> String {
        match &self.project {
            Some(project) => format!("{}/{}/{}", self.organization, project, self.environment),
            None => format!("{}/{}", self.organization, self.environment),
        }
    }

    fn resolve_auth(&self) -> Result<(String, String)> {
        if let Some(token) = self.token.clone() {
            let base = std::env::var("PULUMI_BACKEND_URL")
                .unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
            return Ok((base, token));
        }
        resolve_auth().map_err(|details| FnoxError::ProviderAuthFailed {
            provider: "Pulumi ESC".to_string(),
            details,
            hint: "Run 'esc login' or set PULUMI_ACCESS_TOKEN".to_string(),
            url: URL.to_string(),
        })
    }
}

#[derive(Deserialize)]
struct OpenResponse {
    id: String,
}

/// Walk the resolved `properties` tree for a dot-path reference like
/// `anthropic.api_key`. Every node is wrapped in `{value, trace}`, so we unwrap
/// `.value` after each segment.
fn lookup(root: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = root.pointer("/properties")?;
    for segment in path.split('.') {
        cur = cur.get(segment)?.get("value")?;
    }
    match cur {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Single-pass `<sigil>{path}` substitution against the resolved `properties`
/// tree. Scans left-to-right; the replacement text is NOT rescanned, so
/// `%{foo.%{bar}}` parses as `%{foo.%{bar}` (path `foo.%{bar`), which fails
/// lookup and errors. Any missing reference is a hard error.
fn resolve_refs(raw: &str, root: &serde_json::Value, sigil: char) -> Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    let open: String = format!("{sigil}{{");
    while let Some(start) = rest.find(&open) {
        out.push_str(&rest[..start]);
        let after_open = &rest[start + open.len()..];
        let end = after_open
            .find('}')
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Pulumi ESC".to_string(),
                details: format!("Unterminated '{open}' in value: {raw}"),
                hint: "Add a closing '}' or disable `interpolate` in the lease config".to_string(),
                url: URL.to_string(),
            })?;
        let path = &after_open[..end];
        let resolved = lookup(root, path).ok_or_else(|| FnoxError::ProviderInvalidResponse {
            provider: "Pulumi ESC".to_string(),
            details: format!("Unresolved reference '{open}{path}}}' in value"),
            hint: "Check the path exists in this environment's `properties` tree".to_string(),
            url: URL.to_string(),
        })?;
        out.push_str(&resolved);
        rest = &after_open[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Unwrap one `{value, trace}` entry from `properties.environmentVariables.value`.
/// The inner `.value` is usually a string, but ESC passes booleans and numbers
/// through verbatim — coerce those to their JSON-string form so they can be
/// exported as env vars.
fn extract_value(wrapped: Option<&serde_json::Value>) -> Option<String> {
    let inner = wrapped?.get("value")?;
    match inner {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Null => None,
        _ => None,
    }
}

async fn http_error(resp: reqwest::Response) -> FnoxError {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        FnoxError::ProviderAuthFailed {
            provider: "Pulumi ESC".to_string(),
            details: format!("HTTP {status}: {body}"),
            hint: "Run 'esc login' or check PULUMI_ACCESS_TOKEN".to_string(),
            url: URL.to_string(),
        }
    } else {
        FnoxError::ProviderApiError {
            provider: "Pulumi ESC".to_string(),
            details: format!("HTTP {status}: {body}"),
            hint: "Check organization/project/environment in your lease config".to_string(),
            url: URL.to_string(),
        }
    }
}

#[async_trait]
impl LeaseBackend for PulumiEscBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let env_ref = self.env_ref();
        tracing::debug!(
            "Opening Pulumi ESC env '{}' (label='{}', duration={}s)",
            env_ref,
            label,
            duration.as_secs()
        );

        let (base_url, token) = self.resolve_auth()?;
        let base = base_url.trim_end_matches('/');
        let auth = format!("token {token}");
        let client = crate::http::http_client();
        let duration_param = format!("{}s", duration.as_secs());

        let open_url = format!("{base}/api/esc/environments/{env_ref}/open");
        let open_resp = client
            .post(&open_url)
            .header("Authorization", &auth)
            .query(&[("duration", duration_param.as_str())])
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Pulumi ESC".to_string(),
                details: e.to_string(),
                hint: "Failed to reach Pulumi Cloud".to_string(),
                url: URL.to_string(),
            })?;
        if !open_resp.status().is_success() {
            return Err(http_error(open_resp).await);
        }
        let open: OpenResponse =
            open_resp
                .json()
                .await
                .map_err(|e| FnoxError::ProviderInvalidResponse {
                    provider: "Pulumi ESC".to_string(),
                    details: format!("Failed to parse open response: {e}"),
                    hint: "Unexpected response from Pulumi ESC 'open' endpoint".to_string(),
                    url: URL.to_string(),
                })?;

        let read_url = format!("{base}/api/esc/environments/{env_ref}/open/{}", open.id);
        let read_resp = client
            .get(&read_url)
            .header("Authorization", &auth)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Pulumi ESC".to_string(),
                details: e.to_string(),
                hint: "Failed to read opened ESC environment".to_string(),
                url: URL.to_string(),
            })?;
        if !read_resp.status().is_success() {
            return Err(http_error(read_resp).await);
        }
        let body: serde_json::Value =
            read_resp
                .json()
                .await
                .map_err(|e| FnoxError::ProviderInvalidResponse {
                    provider: "Pulumi ESC".to_string(),
                    details: format!("Failed to parse environment response: {e}"),
                    hint: "Unexpected response from Pulumi ESC".to_string(),
                    url: URL.to_string(),
                })?;

        let env_vars_obj = body
            .pointer("/properties/environmentVariables/value")
            .and_then(|v| v.as_object())
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Pulumi ESC".to_string(),
                details: "Opened environment has no 'environmentVariables' block".to_string(),
                hint: "Add an environmentVariables block to the ESC environment".to_string(),
                url: URL.to_string(),
            })?;

        let mut credentials = IndexMap::new();
        match &self.env_vars {
            Some(filter) => {
                for name in filter {
                    match extract_value(env_vars_obj.get(name)) {
                        Some(val) => {
                            credentials.insert(name.clone(), val);
                        }
                        None => {
                            tracing::warn!(
                                "Pulumi ESC env '{}' did not include '{}'",
                                env_ref,
                                name
                            );
                        }
                    }
                }
            }
            None => {
                for (name, wrapped) in env_vars_obj {
                    if let Some(val) = extract_value(Some(wrapped)) {
                        credentials.insert(name.clone(), val);
                    }
                }
            }
        }

        if credentials.is_empty() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "Pulumi ESC".to_string(),
                details: "No environment variables surfaced from ESC environment".to_string(),
                hint: "Check the ESC environment defines environmentVariables and that 'env_vars' (if set) matches".to_string(),
                url: URL.to_string(),
            });
        }

        if let Some(sigil) = self.interpolate {
            for val in credentials.values_mut() {
                *val = resolve_refs(val, &body, sigil)?;
            }
        }

        let expires_at =
            Some(chrono::Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64));
        let lease_id = super::generate_lease_id(&format!("pulumi-esc-{}", env_ref));

        Ok(Lease {
            credentials,
            expires_at,
            lease_id,
        })
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ref_with_project() {
        let b = PulumiEscBackend::new(
            "myorg".into(),
            Some("proj".into()),
            "dev".into(),
            None,
            None,
            None,
        );
        assert_eq!(b.env_ref(), "myorg/proj/dev");
    }

    #[test]
    fn env_ref_without_project() {
        let b = PulumiEscBackend::new("myorg".into(), None, "dev".into(), None, None, None);
        assert_eq!(b.env_ref(), "myorg/dev");
    }

    fn sample_body() -> serde_json::Value {
        serde_json::json!({
            "properties": {
                "anthropic": {
                    "value": {
                        "api_key": {"value": "sk-test-123"}
                    }
                },
                "aws": {
                    "value": {
                        "region": {"value": "us-west-2"},
                        "port": {"value": 5432}
                    }
                }
            }
        })
    }

    #[test]
    fn lookup_walks_value_wrappers() {
        let body = sample_body();
        assert_eq!(
            lookup(&body, "anthropic.api_key"),
            Some("sk-test-123".to_string())
        );
        assert_eq!(lookup(&body, "aws.region"), Some("us-west-2".to_string()));
        assert_eq!(lookup(&body, "aws.port"), Some("5432".to_string()));
        assert_eq!(lookup(&body, "nope.missing"), None);
    }

    #[test]
    fn resolve_refs_basic_substitution() {
        let body = sample_body();
        let out = resolve_refs("key=%{anthropic.api_key};", &body, '%').unwrap();
        assert_eq!(out, "key=sk-test-123;");
    }

    #[test]
    fn resolve_refs_no_sigil_pass_through() {
        let body = sample_body();
        assert_eq!(
            resolve_refs("plain value", &body, '%').unwrap(),
            "plain value"
        );
    }

    #[test]
    fn resolve_refs_multiple_refs() {
        let body = sample_body();
        let out = resolve_refs("%{anthropic.api_key}|%{aws.region}", &body, '%').unwrap();
        assert_eq!(out, "sk-test-123|us-west-2");
    }

    #[test]
    fn resolve_refs_missing_is_error() {
        let body = sample_body();
        let err = resolve_refs("%{missing.path}", &body, '%').unwrap_err();
        assert!(matches!(err, FnoxError::ProviderInvalidResponse { .. }));
    }

    #[test]
    fn resolve_refs_unterminated_is_error() {
        let body = sample_body();
        let err = resolve_refs("%{anthropic.api_key", &body, '%').unwrap_err();
        assert!(matches!(err, FnoxError::ProviderInvalidResponse { .. }));
    }

    #[test]
    fn resolve_refs_is_single_pass_not_recursive() {
        // `%{foo.%{bar}}` — non-greedy scan consumes up to the first `}`, yielding
        // path `foo.%{bar`, which does not exist → error (no recursion).
        let body = sample_body();
        let err = resolve_refs("%{foo.%{bar}}", &body, '%').unwrap_err();
        assert!(matches!(err, FnoxError::ProviderInvalidResponse { .. }));
    }

    #[test]
    fn resolve_refs_alternate_sigil() {
        let body = sample_body();
        assert_eq!(
            resolve_refs("${aws.region}", &body, '$').unwrap(),
            "us-west-2"
        );
    }

    #[test]
    fn parse_credentials_accounts_variant() {
        let json = r#"{
            "current": "https://api.pulumi.com",
            "accessTokens": {"https://api.pulumi.com": "fallback-token"},
            "accounts": {
                "https://api.pulumi.com": {"accessToken": "primary-token"}
            }
        }"#;
        let creds: PulumiCredentials = serde_json::from_str(json).unwrap();
        assert_eq!(creds.current.as_deref(), Some("https://api.pulumi.com"));
        assert_eq!(
            creds
                .accounts
                .get("https://api.pulumi.com")
                .and_then(|a| a.access_token.as_deref()),
            Some("primary-token")
        );
        assert_eq!(
            creds
                .access_tokens
                .get("https://api.pulumi.com")
                .map(String::as_str),
            Some("fallback-token")
        );
    }

    #[test]
    fn extract_value_handles_scalar_types() {
        let s = serde_json::json!({"value": "hello", "trace": {}});
        assert_eq!(extract_value(Some(&s)), Some("hello".to_string()));
        let b = serde_json::json!({"value": false});
        assert_eq!(extract_value(Some(&b)), Some("false".to_string()));
        let n = serde_json::json!({"value": 42});
        assert_eq!(extract_value(Some(&n)), Some("42".to_string()));
        let null = serde_json::json!({"value": null});
        assert_eq!(extract_value(Some(&null)), None);
        let missing = serde_json::json!({"trace": {}});
        assert_eq!(extract_value(Some(&missing)), None);
        assert_eq!(extract_value(None), None);
    }

    #[test]
    fn parse_credentials_tokens_only() {
        let json = r#"{
            "current": "https://api.pulumi.com",
            "accessTokens": {"https://api.pulumi.com": "tok"}
        }"#;
        let creds: PulumiCredentials = serde_json::from_str(json).unwrap();
        assert!(creds.accounts.is_empty());
        assert_eq!(
            creds
                .access_tokens
                .get("https://api.pulumi.com")
                .map(String::as_str),
            Some("tok")
        );
    }
}
