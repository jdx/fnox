use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::process::Command;

const PROVIDER_NAME: &str = "Doppler";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/doppler";

pub struct DopplerProvider {
    project: Option<String>,
    config: Option<String>,
    token: Option<String>,
}

impl DopplerProvider {
    pub fn new(
        project: Option<String>,
        config: Option<String>,
        token: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            project,
            config,
            token,
        })
    }

    /// Get authentication token from config or environment
    fn get_token(&self) -> Option<String> {
        self.token
            .clone()
            .or_else(|| {
                env::var("FNOX_DOPPLER_TOKEN")
                    .or_else(|_| env::var("DOPPLER_TOKEN"))
                    .ok()
            })
    }

    /// Build common args for project/config/token
    fn build_common_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(ref project) = self.project {
            args.push(format!("--project={}", project));
        }
        if let Some(ref config) = self.config {
            args.push(format!("--config={}", config));
        }
        if let Some(ref token) = self.get_token() {
            args.push(format!("--token={}", token));
        }

        args
    }

    /// Execute a doppler CLI command and return stdout
    async fn execute_doppler_command(
        &self,
        args: &[&str],
        secret_ref: Option<&str>,
    ) -> Result<String> {
        tracing::debug!("Executing doppler command with args: {:?}", args);

        let mut cmd = Command::new("doppler");
        cmd.args(args);

        let common_args = self.build_common_args();
        for arg in &common_args {
            cmd.arg(arg);
        }

        cmd.stdin(std::process::Stdio::null());

        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: PROVIDER_NAME.to_string(),
                    cli: "doppler".to_string(),
                    install_hint: "brew install dopplerhq/cli/doppler".to_string(),
                    url: PROVIDER_URL.to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details: e.to_string(),
                    hint: "Check that the Doppler CLI is installed and accessible".to_string(),
                    url: PROVIDER_URL.to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_cli_error(stderr.trim(), secret_ref));
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for DopplerProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Doppler", value);

        let result = self
            .execute_doppler_command(&["secrets", "get", value, "--plain"], Some(value))
            .await?;

        if result.is_empty() {
            return Err(FnoxError::ProviderSecretNotFound {
                provider: PROVIDER_NAME.to_string(),
                secret: value.to_string(),
                hint: "Check that the secret exists in your Doppler project/config".to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }

        Ok(result)
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

        tracing::debug!("Batch fetching {} secrets from Doppler", secrets.len());

        // Build command: doppler secrets get NAME1 NAME2 ... --json
        let mut args = vec!["secrets", "get"];
        let secret_names: Vec<&str> = secrets.iter().map(|(_, v)| v.as_str()).collect();
        args.extend(&secret_names);
        args.push("--json");

        match self.execute_doppler_command(&args, None).await {
            Ok(json_output) => {
                // Doppler --json returns: { "NAME": { "computed": "value", ... }, ... }
                match serde_json::from_str::<serde_json::Value>(&json_output) {
                    Ok(json_obj) => {
                        secrets
                            .iter()
                            .map(|(key, secret_name)| {
                                let result = json_obj
                                    .get(secret_name)
                                    .and_then(|entry| entry.get("computed"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .ok_or_else(|| FnoxError::ProviderSecretNotFound {
                                        provider: PROVIDER_NAME.to_string(),
                                        secret: secret_name.clone(),
                                        hint: "Check that the secret exists in your Doppler project/config".to_string(),
                                        url: PROVIDER_URL.to_string(),
                                    });
                                (key.clone(), result)
                            })
                            .collect()
                    }
                    Err(e) => secrets
                        .iter()
                        .map(|(key, _)| {
                            (
                                key.clone(),
                                Err(FnoxError::ProviderInvalidResponse {
                                    provider: PROVIDER_NAME.to_string(),
                                    details: format!("Failed to parse batch response: {}", e),
                                    hint: "The Doppler CLI returned an unexpected response format"
                                        .to_string(),
                                    url: PROVIDER_URL.to_string(),
                                }),
                            )
                        })
                        .collect(),
                }
            }
            Err(e) => secrets
                .iter()
                .map(|(key, secret_name)| (key.clone(), Err(map_batch_error(&e, secret_name))))
                .collect(),
        }
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Doppler");

        // Use `doppler secrets --only-names` as a lightweight connectivity check
        self.execute_doppler_command(&["secrets", "--only-names"], None)
            .await?;

        tracing::debug!("Doppler connection test successful");
        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &["DOPPLER_TOKEN", "FNOX_DOPPLER_TOKEN"]
}

fn clone_provider_error(error: &FnoxError) -> Option<FnoxError> {
    Some(match error {
        FnoxError::ProviderAuthFailed {
            provider,
            details,
            hint,
            url,
        } => FnoxError::ProviderAuthFailed {
            provider: provider.clone(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderCliNotFound {
            provider,
            cli,
            install_hint,
            url,
        } => FnoxError::ProviderCliNotFound {
            provider: provider.clone(),
            cli: cli.clone(),
            install_hint: install_hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderInvalidResponse {
            provider,
            details,
            hint,
            url,
        } => FnoxError::ProviderInvalidResponse {
            provider: provider.clone(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderApiError {
            provider,
            details,
            hint,
            url,
        } => FnoxError::ProviderApiError {
            provider: provider.clone(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderCliFailed {
            provider,
            details,
            hint,
            url,
        } => FnoxError::ProviderCliFailed {
            provider: provider.clone(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        _ => return None,
    })
}

/// Map a batch-level error to a per-secret error, preserving structured variants.
fn map_batch_error(e: &FnoxError, secret_name: &str) -> FnoxError {
    if let FnoxError::ProviderSecretNotFound {
        provider,
        hint,
        url,
        ..
    } = e
    {
        return FnoxError::ProviderSecretNotFound {
            provider: provider.clone(),
            secret: secret_name.to_string(),
            hint: hint.clone(),
            url: url.clone(),
        };
    }

    clone_provider_error(e).unwrap_or_else(|| FnoxError::ProviderCliFailed {
        provider: PROVIDER_NAME.to_string(),
        details: e.to_string(),
        hint: "Check your Doppler configuration".to_string(),
        url: PROVIDER_URL.to_string(),
    })
}

const AUTH_ERROR_PATTERNS: &[&str] = &[
    "unauthorized",
    "token expired",
    "invalid token",
    "authentication failed",
    "forbidden",
    "invalid service token",
    "missing token",
];

const SECRET_NOT_FOUND_PATTERNS: &[&str] = &[
    "could not find secret",
    "secret not found",
    "does not exist",
    "not found",
];

const RESOURCE_NOT_FOUND_PATTERNS: &[&str] = &[
    "project not found",
    "config not found",
    "could not find project",
    "could not find config",
    "could not find environment",
];

fn contains_any(haystack: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| haystack.contains(pattern))
}

/// Classify CLI stderr output into the appropriate FnoxError variant.
fn classify_cli_error(stderr: &str, secret_ref: Option<&str>) -> FnoxError {
    let stderr_lower = stderr.to_lowercase();

    if contains_any(&stderr_lower, AUTH_ERROR_PATTERNS) {
        return FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details: stderr.to_string(),
            hint: "Run 'doppler login' or check your DOPPLER_TOKEN".to_string(),
            url: PROVIDER_URL.to_string(),
        };
    }

    if contains_any(&stderr_lower, RESOURCE_NOT_FOUND_PATTERNS) {
        return FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details: stderr.to_string(),
            hint: "Check project/config settings in your Doppler provider config".to_string(),
            url: PROVIDER_URL.to_string(),
        };
    }

    if let Some(secret_name) = secret_ref
        && contains_any(&stderr_lower, SECRET_NOT_FOUND_PATTERNS)
    {
        return FnoxError::ProviderSecretNotFound {
            provider: PROVIDER_NAME.to_string(),
            secret: secret_name.to_string(),
            hint: "Check that the secret exists in your Doppler project/config".to_string(),
            url: PROVIDER_URL.to_string(),
        };
    }

    FnoxError::ProviderCliFailed {
        provider: PROVIDER_NAME.to_string(),
        details: stderr.to_string(),
        hint: "Check your Doppler configuration and authentication".to_string(),
        url: PROVIDER_URL.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_cli_error_unauthorized() {
        let err = classify_cli_error("Error: Unauthorized access", Some("MY_SECRET"));
        assert!(
            matches!(err, FnoxError::ProviderAuthFailed { .. }),
            "Expected ProviderAuthFailed, got {:?}",
            err
        );
    }

    #[test]
    fn classify_cli_error_invalid_service_token() {
        let err = classify_cli_error("Invalid service token", None);
        assert!(matches!(err, FnoxError::ProviderAuthFailed { .. }));
    }

    #[test]
    fn classify_cli_error_project_not_found() {
        let err = classify_cli_error("Could not find project", Some("SECRET"));
        assert!(
            matches!(err, FnoxError::ProviderApiError { .. }),
            "Expected ProviderApiError, got {:?}",
            err
        );
    }

    #[test]
    fn classify_cli_error_config_not_found() {
        let err = classify_cli_error("Could not find config", Some("SECRET"));
        assert!(
            matches!(err, FnoxError::ProviderApiError { .. }),
            "Expected ProviderApiError, got {:?}",
            err
        );
    }

    #[test]
    fn classify_cli_error_secret_not_found() {
        let err = classify_cli_error("Could not find secret NAME", Some("NAME"));
        match err {
            FnoxError::ProviderSecretNotFound { secret, .. } => {
                assert_eq!(secret, "NAME");
            }
            other => panic!("Expected ProviderSecretNotFound, got {:?}", other),
        }
    }

    #[test]
    fn classify_cli_error_secret_not_found_without_ref() {
        let err = classify_cli_error("Could not find secret", None);
        assert!(
            matches!(err, FnoxError::ProviderCliFailed { .. }),
            "Expected ProviderCliFailed, got {:?}",
            err
        );
    }

    #[test]
    fn classify_cli_error_generic() {
        let err = classify_cli_error("some unexpected error", Some("SECRET"));
        assert!(
            matches!(err, FnoxError::ProviderCliFailed { .. }),
            "Expected ProviderCliFailed, got {:?}",
            err
        );
    }

    #[test]
    fn map_batch_error_preserves_auth_failed() {
        let error = FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details: "unauthorized".to_string(),
            hint: "login".to_string(),
            url: PROVIDER_URL.to_string(),
        };

        let result = map_batch_error(&error, "secret1");
        assert!(
            matches!(result, FnoxError::ProviderAuthFailed { .. }),
            "Expected ProviderAuthFailed, got {:?}",
            result
        );
    }

    #[test]
    fn map_batch_error_preserves_secret_not_found_with_per_secret_name() {
        let error = FnoxError::ProviderSecretNotFound {
            provider: PROVIDER_NAME.to_string(),
            secret: "original".to_string(),
            hint: "check".to_string(),
            url: PROVIDER_URL.to_string(),
        };

        let result = map_batch_error(&error, "secret_a");
        match result {
            FnoxError::ProviderSecretNotFound { secret, .. } => {
                assert_eq!(secret, "secret_a");
            }
            other => panic!("Expected ProviderSecretNotFound, got {:?}", other),
        }
    }
}
