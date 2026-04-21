use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::process::Command;

const PROVIDER_NAME: &str = "Pulumi ESC";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/pulumi-esc";
const CLI: &str = "esc";

pub struct PulumiEscProvider {
    organization: String,
    project: Option<String>,
    environment: String,
    token: Option<String>,
}

impl PulumiEscProvider {
    pub fn new(
        organization: String,
        project: Option<String>,
        environment: String,
        token: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            organization,
            project,
            environment,
            token,
        })
    }

    /// Resolve the access token from config or environment.
    fn get_token(&self) -> Option<String> {
        self.token.clone().or_else(|| {
            env::var("FNOX_PULUMI_ACCESS_TOKEN")
                .or_else(|_| env::var("PULUMI_ACCESS_TOKEN"))
                .ok()
        })
    }

    /// Build the environment reference as `<org>/<project>/<env>` (modern) or
    /// `<org>/<env>` (legacy) when no project is configured.
    fn env_ref(&self) -> String {
        match &self.project {
            Some(project) => format!("{}/{}/{}", self.organization, project, self.environment),
            None => format!("{}/{}", self.organization, self.environment),
        }
    }

    async fn execute_esc_command(&self, args: &[&str], secret_ref: Option<&str>) -> Result<String> {
        tracing::debug!("Executing esc command with args: {:?}", args);

        let mut cmd = Command::new(CLI);
        cmd.args(args);

        if let Some(token) = self.get_token() {
            cmd.env("PULUMI_ACCESS_TOKEN", token);
        }

        cmd.stdin(std::process::Stdio::null());

        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: PROVIDER_NAME.to_string(),
                    cli: CLI.to_string(),
                    install_hint: "brew install pulumi/tap/esc".to_string(),
                    url: PROVIDER_URL.to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details: e.to_string(),
                    hint: "Check that the esc CLI is installed and accessible".to_string(),
                    url: PROVIDER_URL.to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_cli_error(stderr.trim(), secret_ref));
        }

        String::from_utf8(output.stdout)
            .map(|s| s.trim_end_matches('\n').to_string())
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: PROVIDER_URL.to_string(),
            })
    }
}

#[async_trait]
impl crate::providers::Provider for PulumiEscProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Pulumi ESC", value);

        let env_ref = self.env_ref();
        self.execute_esc_command(
            &[
                "env",
                "get",
                &env_ref,
                value,
                "--value",
                "string",
                "--show-secrets",
            ],
            Some(value),
        )
        .await
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        if secrets.is_empty() {
            return HashMap::new();
        }
        if secrets.len() == 1 {
            let (key, value) = &secrets[0];
            let result = self.get_secret(value).await;
            let mut map = HashMap::new();
            map.insert(key.clone(), result);
            return map;
        }

        tracing::debug!("Batch fetching {} secrets from Pulumi ESC", secrets.len());

        // Open the environment once, retrieve the full resolved JSON, and extract paths locally.
        let env_ref = self.env_ref();
        match self
            .execute_esc_command(&["env", "open", &env_ref, "--format", "json"], None)
            .await
        {
            Ok(json_output) => match serde_json::from_str::<serde_json::Value>(&json_output) {
                Ok(json_root) => secrets
                    .iter()
                    .map(|(key, path)| {
                        let result = extract_path(&json_root, path).ok_or_else(|| {
                            FnoxError::ProviderSecretNotFound {
                                provider: PROVIDER_NAME.to_string(),
                                secret: path.clone(),
                                hint: "Check that the path exists in your Pulumi ESC environment"
                                    .to_string(),
                                url: PROVIDER_URL.to_string(),
                            }
                        });
                        (key.clone(), result)
                    })
                    .collect(),
                Err(e) => secrets
                    .iter()
                    .map(|(key, _)| {
                        (
                            key.clone(),
                            Err(FnoxError::ProviderInvalidResponse {
                                provider: PROVIDER_NAME.to_string(),
                                details: format!("Failed to parse batch response: {}", e),
                                hint: "The esc CLI returned an unexpected response format"
                                    .to_string(),
                                url: PROVIDER_URL.to_string(),
                            }),
                        )
                    })
                    .collect(),
            },
            Err(e) => secrets
                .iter()
                .map(|(key, secret_name)| {
                    (
                        key.clone(),
                        e.map_batch_error(
                            secret_name,
                            PROVIDER_NAME,
                            "Check your Pulumi ESC configuration",
                            PROVIDER_URL,
                        ),
                    )
                })
                .map(|(k, v)| (k, Err(v)))
                .collect(),
        }
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Pulumi ESC");

        // `esc env ls` is a lightweight call that validates authentication and API access.
        self.execute_esc_command(&["env", "ls"], None).await?;

        tracing::debug!("Pulumi ESC connection test successful");
        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &["PULUMI_ACCESS_TOKEN", "FNOX_PULUMI_ACCESS_TOKEN"]
}

/// Navigate a JSON value using a dot-delimited path (e.g. `database.password`).
///
/// Pulumi ESC `esc env open --format json` emits the resolved values under a top-level
/// `environmentVariables` and nested `values` structure. Secret paths in fnox configs
/// are written just as the user references them in `esc env get`, so we walk both the
/// root and the common `values` container to find the requested path.
fn extract_path(root: &serde_json::Value, path: &str) -> Option<String> {
    if let Some(v) = walk(root, path) {
        return value_to_string(v);
    }
    // ESC exposes user-defined keys under `values.*` when opening an environment.
    if let Some(values) = root.get("values")
        && let Some(v) = walk(values, path)
    {
        return value_to_string(v);
    }
    None
}

fn walk<'a>(mut current: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        // Non-string leaves (numbers, bools) are serialized as their JSON form.
        // Objects/arrays are returned as JSON so callers can still consume them.
        other => Some(other.to_string()),
    }
}

const AUTH_ERROR_PATTERNS: &[&str] = &[
    "unauthorized",
    "401",
    "403",
    "invalid access token",
    "access token",
    "not logged in",
    "please run `pulumi login`",
    "please run `esc login`",
];

const SECRET_NOT_FOUND_PATTERNS: &[&str] = &[
    "no value",
    "path not found",
    "does not exist",
    "unknown property",
    "unknown path",
];

const RESOURCE_NOT_FOUND_PATTERNS: &[&str] = &[
    "environment not found",
    "could not find environment",
    "no such environment",
    "project not found",
    "organization not found",
    "could not find organization",
];

fn contains_any(haystack: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| haystack.contains(pattern))
}

fn classify_cli_error(stderr: &str, secret_ref: Option<&str>) -> FnoxError {
    let stderr_lower = stderr.to_lowercase();

    if contains_any(&stderr_lower, AUTH_ERROR_PATTERNS) {
        return FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details: stderr.to_string(),
            hint: "Run 'esc login' or set PULUMI_ACCESS_TOKEN".to_string(),
            url: PROVIDER_URL.to_string(),
        };
    }

    if contains_any(&stderr_lower, RESOURCE_NOT_FOUND_PATTERNS) {
        return FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details: stderr.to_string(),
            hint: "Check organization/project/environment in your provider config".to_string(),
            url: PROVIDER_URL.to_string(),
        };
    }

    if let Some(secret_name) = secret_ref
        && contains_any(&stderr_lower, SECRET_NOT_FOUND_PATTERNS)
    {
        return FnoxError::ProviderSecretNotFound {
            provider: PROVIDER_NAME.to_string(),
            secret: secret_name.to_string(),
            hint: "Check that the path exists in your Pulumi ESC environment".to_string(),
            url: PROVIDER_URL.to_string(),
        };
    }

    FnoxError::ProviderCliFailed {
        provider: PROVIDER_NAME.to_string(),
        details: stderr.to_string(),
        hint: "Check your Pulumi ESC configuration and authentication".to_string(),
        url: PROVIDER_URL.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn env_ref_with_project() {
        let p = PulumiEscProvider::new("myorg".into(), Some("myproj".into()), "dev".into(), None)
            .unwrap();
        assert_eq!(p.env_ref(), "myorg/myproj/dev");
    }

    #[test]
    fn env_ref_without_project() {
        let p = PulumiEscProvider::new("myorg".into(), None, "dev".into(), None).unwrap();
        assert_eq!(p.env_ref(), "myorg/dev");
    }

    #[test]
    fn extract_path_from_values() {
        let root = json!({
            "values": {
                "database": { "password": "s3cret" },
                "apiKey": "abc"
            }
        });
        assert_eq!(
            extract_path(&root, "database.password"),
            Some("s3cret".to_string())
        );
        assert_eq!(extract_path(&root, "apiKey"), Some("abc".to_string()));
    }

    #[test]
    fn extract_path_from_root() {
        let root = json!({ "foo": "bar" });
        assert_eq!(extract_path(&root, "foo"), Some("bar".to_string()));
    }

    #[test]
    fn extract_path_missing() {
        let root = json!({ "values": { "a": 1 } });
        assert_eq!(extract_path(&root, "nope"), None);
    }

    #[test]
    fn extract_path_non_string_leaf() {
        let root = json!({ "values": { "port": 5432 } });
        assert_eq!(extract_path(&root, "port"), Some("5432".to_string()));
    }

    #[test]
    fn classify_unauthorized_is_auth_failed() {
        let err = classify_cli_error("error: 401 unauthorized", Some("X"));
        assert!(matches!(err, FnoxError::ProviderAuthFailed { .. }));
    }

    #[test]
    fn classify_invalid_access_token_is_auth_failed() {
        let err = classify_cli_error("invalid access token", None);
        assert!(matches!(err, FnoxError::ProviderAuthFailed { .. }));
    }

    #[test]
    fn classify_environment_not_found_is_api_error() {
        let err = classify_cli_error("environment not found", Some("X"));
        assert!(matches!(err, FnoxError::ProviderApiError { .. }));
    }

    #[test]
    fn classify_path_not_found_is_secret_not_found() {
        let err = classify_cli_error("path not found: foo", Some("foo"));
        match err {
            FnoxError::ProviderSecretNotFound { secret, .. } => assert_eq!(secret, "foo"),
            other => panic!("expected ProviderSecretNotFound, got {:?}", other),
        }
    }

    #[test]
    fn classify_generic_is_cli_failed() {
        let err = classify_cli_error("boom", Some("X"));
        assert!(matches!(err, FnoxError::ProviderCliFailed { .. }));
    }
}
