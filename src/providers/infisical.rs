use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::process::Command;
use std::sync::{LazyLock, Mutex};

pub struct InfisicalProvider {
    project_id: Option<String>,
    environment: Option<String>,
    path: Option<String>,
}

impl InfisicalProvider {
    pub fn new(
        project_id: Option<String>,
        environment: Option<String>,
        path: Option<String>,
    ) -> Self {
        Self {
            project_id,
            environment,
            path,
        }
    }

    /// Get authentication token - either from environment or by logging in with client credentials
    fn get_auth_token(&self) -> Result<String> {
        // Check if we already have a token
        if let Some(token) = infisical_token() {
            tracing::debug!("Using INFISICAL_TOKEN from environment");
            return Ok(token);
        }

        // Check if we have client credentials to obtain a token
        let client_id = infisical_client_id().ok_or_else(|| FnoxError::ProviderAuthFailed {
            provider: "Infisical".to_string(),
            details: "Authentication not found".to_string(),
            hint: "Set INFISICAL_TOKEN, or both INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET"
                .to_string(),
            url: "https://fnox.jdx.dev/providers/infisical".to_string(),
        })?;

        let client_secret =
            infisical_client_secret().ok_or_else(|| FnoxError::ProviderAuthFailed {
                provider: "Infisical".to_string(),
                details: "Client secret not found".to_string(),
                hint: "Set INFISICAL_CLIENT_SECRET or FNOX_INFISICAL_CLIENT_SECRET".to_string(),
                url: "https://fnox.jdx.dev/providers/infisical".to_string(),
            })?;

        // Acquire lock for the entire check-and-login operation to prevent race condition
        // where multiple threads might all see no cached token and perform expensive login operations
        let mut cached_token = CACHED_LOGIN_TOKEN.lock().unwrap();

        // Check if another thread cached a token while we were waiting for the lock
        if let Some(token) = cached_token.as_ref() {
            tracing::debug!("Using cached login token");
            return Ok(token.clone());
        }

        tracing::debug!("Logging in with Universal Auth credentials");

        // Login with client credentials to get a token
        let mut cmd = Command::new("infisical");
        cmd.args([
            "login",
            "--method",
            "universal-auth",
            "--client-id",
            &client_id,
            "--client-secret",
            &client_secret,
            "--plain",
            "--silent",
        ]);

        // Add custom domain if specified, stripping /api suffix if present
        // The CLI's --domain flag expects base URL (some commands append /api automatically)
        if let Some(api_url) = infisical_api_url() {
            let base_url = api_url.trim_end_matches("/api").trim_end_matches('/');
            cmd.arg("--domain");
            cmd.arg(base_url);
            tracing::debug!(
                "Using custom Infisical domain: {} (from: {})",
                base_url,
                api_url
            );
        }

        cmd.stdin(std::process::Stdio::null());

        let output = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "Infisical".to_string(),
                    cli: "infisical".to_string(),
                    install_hint: "brew install infisical/get-cli/infisical".to_string(),
                    url: "https://fnox.jdx.dev/providers/infisical".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "Infisical".to_string(),
                    details: e.to_string(),
                    hint: "Check that the Infisical CLI is installed and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/infisical".to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::ProviderAuthFailed {
                provider: "Infisical".to_string(),
                details: stderr.trim().to_string(),
                hint: "Check your client ID and client secret".to_string(),
                url: "https://fnox.jdx.dev/providers/infisical".to_string(),
            });
        }

        let token = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Infisical".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "This is an unexpected error".to_string(),
                url: "https://fnox.jdx.dev/providers/infisical".to_string(),
            })?
            .trim()
            .to_string();

        // Cache the token (lock still held, preventing race condition)
        *cached_token = Some(token.clone());

        tracing::debug!("Successfully logged in and cached token");

        Ok(token)
    }

    /// Execute infisical CLI command.
    /// `secret_ref` is used for better error messages when a specific secret is being fetched.
    fn execute_infisical_command(
        &self,
        args: &[&str],
        secret_ref: Option<&str>,
    ) -> Result<String> {
        tracing::debug!("Executing infisical command with args: {:?}", args);

        let token = self.get_auth_token()?;

        let mut cmd = Command::new("infisical");
        cmd.args(args);

        // Add authentication token
        cmd.arg("--token");
        cmd.arg(&token);

        // Add custom domain if specified, stripping /api suffix if present
        // The CLI's --domain flag expects base URL (some commands append /api automatically)
        if let Some(api_url) = infisical_api_url() {
            let base_url = api_url.trim_end_matches("/api").trim_end_matches('/');
            cmd.arg("--domain");
            cmd.arg(base_url);
        }

        // Add silent flag to reduce noise
        cmd.arg("--silent");

        cmd.stdin(std::process::Stdio::null());

        let output = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "Infisical".to_string(),
                    cli: "infisical".to_string(),
                    install_hint: "brew install infisical/get-cli/infisical".to_string(),
                    url: "https://fnox.jdx.dev/providers/infisical".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "Infisical".to_string(),
                    details: e.to_string(),
                    hint: "Check that the Infisical CLI is installed and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/infisical".to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_cli_error(stderr.trim(), secret_ref));
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Infisical".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: "https://fnox.jdx.dev/providers/infisical".to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for InfisicalProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Infisical", value);

        // Build the command: infisical secrets get <name> --output json
        // Using JSON format allows us to distinguish between "not found" and "empty value"
        let mut args = vec!["secrets", "get", value, "--output", "json"];

        // Add project ID if specified
        let project_arg;
        if let Some(ref project_id) = self.project_id {
            project_arg = format!("--projectId={}", project_id);
            args.push(&project_arg);
        }

        // Add environment if specified (otherwise CLI uses its default: "dev")
        let env_arg;
        if let Some(ref environment) = self.environment {
            env_arg = format!("--env={}", environment);
            args.push(&env_arg);
        }

        // Add path if specified (otherwise CLI uses its default: "/")
        let path_arg;
        if let Some(ref path) = self.path {
            path_arg = format!("--path={}", path);
            args.push(&path_arg);
        }

        tracing::debug!(
            "Fetching secret '{}' with project_id={:?}, environment={:?}, path={:?}",
            value,
            self.project_id,
            self.environment,
            self.path
        );

        let json_output = self.execute_infisical_command(&args, Some(value))?;

        // Parse JSON response - format is an array with one object
        // [{"secretKey": "NAME", "secretValue": "value"}]
        let json_array =
            serde_json::from_str::<Vec<serde_json::Value>>(&json_output).map_err(|e| {
                FnoxError::ProviderInvalidResponse {
                    provider: "Infisical".to_string(),
                    details: format!("Failed to parse response for '{}': {}", value, e),
                    hint: "The Infisical CLI returned an unexpected response format".to_string(),
                    url: "https://fnox.jdx.dev/providers/infisical".to_string(),
                }
            })?;

        // Extract the secret value from the first (and only) object
        if json_array.is_empty() {
            return Err(FnoxError::ProviderSecretNotFound {
                provider: "Infisical".to_string(),
                secret: value.to_string(),
                hint: "Check that the secret exists in Infisical".to_string(),
                url: "https://fnox.jdx.dev/providers/infisical".to_string(),
            });
        }

        let secret_value = json_array[0]
            .get("secretValue")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Infisical".to_string(),
                details: format!(
                    "Invalid response format for '{}' - missing secretValue field",
                    value
                ),
                hint: "The Infisical CLI returned an unexpected response format".to_string(),
                url: "https://fnox.jdx.dev/providers/infisical".to_string(),
            })?;

        // The Infisical CLI returns "*not found*" as a placeholder when a secret doesn't exist
        // Treat this as an error rather than returning the literal placeholder string
        if secret_value == "*not found*" {
            return Err(FnoxError::ProviderSecretNotFound {
                provider: "Infisical".to_string(),
                secret: value.to_string(),
                hint: "Check that the secret exists in Infisical".to_string(),
                url: "https://fnox.jdx.dev/providers/infisical".to_string(),
            });
        }

        Ok(secret_value.to_string())
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        // If empty or single secret, fall back to individual get
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

        tracing::debug!("Batch fetching {} secrets from Infisical", secrets.len());

        // Build command with all secret names
        let mut args = vec!["secrets", "get"];
        let secret_names: Vec<&str> = secrets.iter().map(|(_, v)| v.as_str()).collect();
        args.extend(&secret_names);
        args.push("--output");
        args.push("json");

        // Add project ID if specified
        let project_arg;
        if let Some(ref project_id) = self.project_id {
            project_arg = format!("--projectId={}", project_id);
            args.push(&project_arg);
        }

        // Add environment if specified
        let env_arg;
        if let Some(ref environment) = self.environment {
            env_arg = format!("--env={}", environment);
            args.push(&env_arg);
        }

        // Add path if specified
        let path_arg;
        if let Some(ref path) = self.path {
            path_arg = format!("--path={}", path);
            args.push(&path_arg);
        }

        // Execute command
        match self.execute_infisical_command(&args, None) {
            Ok(json_output) => {
                // Parse JSON response
                match serde_json::from_str::<Vec<serde_json::Value>>(&json_output) {
                    Ok(json_array) => {
                        // Build a map of secret_name -> secret_value from JSON
                        // Skip entries with "*not found*" placeholder (CLI returns this for missing secrets)
                        let mut value_map: HashMap<String, String> = HashMap::new();
                        for item in json_array {
                            if let (Some(name), Some(value)) = (
                                item.get("secretKey").and_then(|v| v.as_str()),
                                item.get("secretValue").and_then(|v| v.as_str()),
                            ) {
                                // Skip placeholder values - treat them as not found
                                if value != "*not found*" {
                                    value_map.insert(name.to_string(), value.to_string());
                                }
                            }
                        }

                        // Map results back to original keys
                        secrets
                            .iter()
                            .map(|(key, secret_name)| {
                                let result = value_map.get(secret_name).cloned().ok_or_else(|| {
                                    FnoxError::ProviderSecretNotFound {
                                        provider: "Infisical".to_string(),
                                        secret: secret_name.clone(),
                                        hint: "Check that the secret exists in Infisical"
                                            .to_string(),
                                        url: "https://fnox.jdx.dev/providers/infisical".to_string(),
                                    }
                                });
                                (key.clone(), result)
                            })
                            .collect()
                    }
                    Err(e) => {
                        // JSON parse error - return same error for all secrets
                        secrets
                            .iter()
                            .map(|(key, _)| {
                                (key.clone(), Err(FnoxError::ProviderInvalidResponse {
                                    provider: "Infisical".to_string(),
                                    details: format!("Failed to parse batch response: {}", e),
                                    hint: "The Infisical CLI returned an unexpected response format".to_string(),
                                    url: "https://fnox.jdx.dev/providers/infisical".to_string(),
                                }))
                            })
                            .collect()
                    }
                }
            }
            Err(e) => {
                // Preserve the structured error variant for each secret
                secrets
                    .iter()
                    .map(|(key, secret_name)| {
                        (key.clone(), Err(map_batch_error(&e, secret_name)))
                    })
                    .collect()
            }
        }
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Infisical");

        // Try to authenticate and get a token
        let _token = self.get_auth_token()?;

        tracing::debug!("Infisical connection test successful");

        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &[
        "INFISICAL_TOKEN",
        "FNOX_INFISICAL_TOKEN",
        "INFISICAL_CLIENT_ID",
        "FNOX_INFISICAL_CLIENT_ID",
        "INFISICAL_CLIENT_SECRET",
        "FNOX_INFISICAL_CLIENT_SECRET",
        "INFISICAL_API_URL",
        "FNOX_INFISICAL_API_URL",
    ]
}

fn infisical_token() -> Option<String> {
    env::var("FNOX_INFISICAL_TOKEN")
        .or_else(|_| env::var("INFISICAL_TOKEN"))
        .ok()
}

fn infisical_client_id() -> Option<String> {
    env::var("FNOX_INFISICAL_CLIENT_ID")
        .or_else(|_| env::var("INFISICAL_CLIENT_ID"))
        .ok()
}

fn infisical_client_secret() -> Option<String> {
    env::var("FNOX_INFISICAL_CLIENT_SECRET")
        .or_else(|_| env::var("INFISICAL_CLIENT_SECRET"))
        .ok()
}

fn infisical_api_url() -> Option<String> {
    env::var("FNOX_INFISICAL_API_URL")
        .or_else(|_| env::var("INFISICAL_API_URL"))
        .ok()
}

// Cache login token to avoid repeated login calls
static CACHED_LOGIN_TOKEN: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// Map a batch-level error to a per-secret error, preserving the structured variant.
fn map_batch_error(e: &FnoxError, secret_name: &str) -> FnoxError {
    match e {
        FnoxError::ProviderAuthFailed {
            details, hint, url, ..
        } => FnoxError::ProviderAuthFailed {
            provider: "Infisical".to_string(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderSecretNotFound { hint, url, .. } => {
            FnoxError::ProviderSecretNotFound {
                provider: "Infisical".to_string(),
                secret: secret_name.to_string(),
                hint: hint.clone(),
                url: url.clone(),
            }
        }
        FnoxError::ProviderCliNotFound {
            cli,
            install_hint,
            url,
            ..
        } => FnoxError::ProviderCliNotFound {
            provider: "Infisical".to_string(),
            cli: cli.clone(),
            install_hint: install_hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderInvalidResponse {
            details, hint, url, ..
        } => FnoxError::ProviderInvalidResponse {
            provider: "Infisical".to_string(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderApiError {
            details, hint, url, ..
        } => FnoxError::ProviderApiError {
            provider: "Infisical".to_string(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderCliFailed {
            details, hint, url, ..
        } => FnoxError::ProviderCliFailed {
            provider: "Infisical".to_string(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        _ => FnoxError::ProviderCliFailed {
            provider: "Infisical".to_string(),
            details: e.to_string(),
            hint: "Check your Infisical configuration".to_string(),
            url: "https://fnox.jdx.dev/providers/infisical".to_string(),
        },
    }
}

/// Classify CLI stderr output into the appropriate FnoxError variant.
fn classify_cli_error(stderr: &str, secret_ref: Option<&str>) -> FnoxError {
    let stderr_lower = stderr.to_lowercase();

    if stderr_lower.contains("unauthorized")
        || stderr_lower.contains("token expired")
        || stderr_lower.contains("invalid token")
        || stderr_lower.contains("authentication failed")
        || stderr_lower.contains("forbidden")
    {
        return FnoxError::ProviderAuthFailed {
            provider: "Infisical".to_string(),
            details: stderr.to_string(),
            hint: "Run 'infisical login' or check your INFISICAL_TOKEN".to_string(),
            url: "https://fnox.jdx.dev/providers/infisical".to_string(),
        };
    }

    if stderr_lower.contains("not found") || stderr_lower.contains("does not exist") {
        return FnoxError::ProviderSecretNotFound {
            provider: "Infisical".to_string(),
            secret: secret_ref.unwrap_or("<unknown>").to_string(),
            hint: "Check that the secret exists in Infisical".to_string(),
            url: "https://fnox.jdx.dev/providers/infisical".to_string(),
        };
    }

    FnoxError::ProviderCliFailed {
        provider: "Infisical".to_string(),
        details: stderr.to_string(),
        hint: "Check your Infisical configuration and authentication".to_string(),
        url: "https://fnox.jdx.dev/providers/infisical".to_string(),
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
    fn classify_cli_error_token_expired() {
        let err = classify_cli_error("token expired, please re-authenticate", None);
        assert!(matches!(err, FnoxError::ProviderAuthFailed { .. }));
    }

    #[test]
    fn classify_cli_error_forbidden() {
        let err = classify_cli_error("403 Forbidden", Some("SECRET"));
        assert!(matches!(err, FnoxError::ProviderAuthFailed { .. }));
    }

    #[test]
    fn classify_cli_error_not_found() {
        let err = classify_cli_error("secret not found in project", Some("MY_SECRET"));
        match err {
            FnoxError::ProviderSecretNotFound { secret, .. } => {
                assert_eq!(secret, "MY_SECRET");
            }
            other => panic!("Expected ProviderSecretNotFound, got {:?}", other),
        }
    }

    #[test]
    fn classify_cli_error_does_not_exist() {
        let err = classify_cli_error("The resource does not exist", Some("DB_PASS"));
        match err {
            FnoxError::ProviderSecretNotFound { secret, .. } => {
                assert_eq!(secret, "DB_PASS");
            }
            other => panic!("Expected ProviderSecretNotFound, got {:?}", other),
        }
    }

    #[test]
    fn classify_cli_error_not_found_without_ref() {
        let err = classify_cli_error("not found", None);
        match err {
            FnoxError::ProviderSecretNotFound { secret, .. } => {
                assert_eq!(secret, "<unknown>");
            }
            other => panic!("Expected ProviderSecretNotFound, got {:?}", other),
        }
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
            provider: "Infisical".to_string(),
            details: "unauthorized".to_string(),
            hint: "login".to_string(),
            url: "https://fnox.jdx.dev/providers/infisical".to_string(),
        };

        let result = map_batch_error(&error, "secret1");
        assert!(
            matches!(result, FnoxError::ProviderAuthFailed { .. }),
            "Expected ProviderAuthFailed, got {:?}",
            result
        );
    }

    #[test]
    fn map_batch_error_preserves_cli_not_found() {
        let error = FnoxError::ProviderCliNotFound {
            provider: "Infisical".to_string(),
            cli: "infisical".to_string(),
            install_hint: "brew install".to_string(),
            url: "https://fnox.jdx.dev/providers/infisical".to_string(),
        };

        let result = map_batch_error(&error, "secret1");
        assert!(
            matches!(result, FnoxError::ProviderCliNotFound { .. }),
            "Expected ProviderCliNotFound, got {:?}",
            result
        );
    }

    #[test]
    fn map_batch_error_preserves_secret_not_found_with_per_secret_name() {
        let error = FnoxError::ProviderSecretNotFound {
            provider: "Infisical".to_string(),
            secret: "original".to_string(),
            hint: "check".to_string(),
            url: "https://fnox.jdx.dev/providers/infisical".to_string(),
        };

        let result = map_batch_error(&error, "secret_a");
        match result {
            FnoxError::ProviderSecretNotFound { secret, .. } => {
                assert_eq!(secret, "secret_a");
            }
            other => panic!("Expected ProviderSecretNotFound, got {:?}", other),
        }
    }

    #[test]
    fn map_batch_error_clones_cli_failed_without_double_wrapping() {
        let error = FnoxError::ProviderCliFailed {
            provider: "Infisical".to_string(),
            details: "some error".to_string(),
            hint: "original hint".to_string(),
            url: "https://fnox.jdx.dev/providers/infisical".to_string(),
        };

        let result = map_batch_error(&error, "secret1");
        match result {
            FnoxError::ProviderCliFailed { details, hint, .. } => {
                assert_eq!(details, "some error");
                assert_eq!(hint, "original hint");
            }
            other => panic!("Expected ProviderCliFailed, got {:?}", other),
        }
    }
}
