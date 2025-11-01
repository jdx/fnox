use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
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
        if let Some(token) = &*INFISICAL_TOKEN {
            tracing::debug!("Using INFISICAL_TOKEN from environment");
            return Ok(token.clone());
        }

        // Check if we have client credentials to obtain a token
        let client_id = INFISICAL_CLIENT_ID
            .as_ref()
            .ok_or_else(|| {
                FnoxError::Provider(
                    "Infisical authentication not found. Please set INFISICAL_TOKEN, or both INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET environment variables."
                        .to_string(),
                )
            })?;

        let client_secret = INFISICAL_CLIENT_SECRET
            .as_ref()
            .ok_or_else(|| {
                FnoxError::Provider(
                    "Infisical client secret not found. Please set INFISICAL_CLIENT_SECRET environment variable or FNOX_INFISICAL_CLIENT_SECRET in your configuration."
                        .to_string(),
                )
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
            client_id,
            "--client-secret",
            client_secret,
            "--plain",
            "--silent",
        ]);

        // Add custom domain if specified, stripping /api suffix if present
        // The CLI's --domain flag expects base URL (some commands append /api automatically)
        if let Some(api_url) = &*INFISICAL_API_URL {
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
            FnoxError::Provider(format!(
                "Failed to execute 'infisical' command: {}. Make sure the Infisical CLI is installed.",
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::Provider(format!(
                "Infisical login failed: {}",
                stderr.trim()
            )));
        }

        let token = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?
            .trim()
            .to_string();

        // Cache the token (lock still held, preventing race condition)
        *cached_token = Some(token.clone());

        tracing::debug!("Successfully logged in and cached token");

        Ok(token)
    }

    /// Execute infisical CLI command
    fn execute_infisical_command(&self, args: &[&str]) -> Result<String> {
        tracing::debug!("Executing infisical command with args: {:?}", args);

        let token = self.get_auth_token()?;

        let mut cmd = Command::new("infisical");
        cmd.args(args);

        // Add authentication token
        cmd.arg("--token");
        cmd.arg(&token);

        // Add custom domain if specified, stripping /api suffix if present
        // The CLI's --domain flag expects base URL (some commands append /api automatically)
        if let Some(api_url) = &*INFISICAL_API_URL {
            let base_url = api_url.trim_end_matches("/api").trim_end_matches('/');
            cmd.arg("--domain");
            cmd.arg(base_url);
        }

        // Add silent flag to reduce noise
        cmd.arg("--silent");

        cmd.stdin(std::process::Stdio::null());

        let output = cmd.output().map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to execute 'infisical' command: {}. Make sure the Infisical CLI is installed.",
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::Provider(format!(
                "Infisical CLI command failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for InfisicalProvider {
    async fn get_secret(&self, value: &str, _key_file: Option<&Path>) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Infisical", value);

        // Build the command: infisical secrets get <name>
        let mut args = vec!["secrets", "get", value, "--plain"];

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

        self.execute_infisical_command(&args)
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
        _key_file: Option<&Path>,
    ) -> HashMap<String, Result<String>> {
        // If empty or single secret, fall back to individual get
        if secrets.is_empty() {
            return HashMap::new();
        }
        if secrets.len() == 1 {
            let (key, value) = &secrets[0];
            let result = self.get_secret(value, _key_file).await;
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
        match self.execute_infisical_command(&args) {
            Ok(json_output) => {
                // Parse JSON response
                match serde_json::from_str::<Vec<serde_json::Value>>(&json_output) {
                    Ok(json_array) => {
                        // Build a map of secret_name -> secret_value from JSON
                        let mut value_map: HashMap<String, String> = HashMap::new();
                        for item in json_array {
                            if let (Some(name), Some(value)) = (
                                item.get("secretKey").and_then(|v| v.as_str()),
                                item.get("secretValue").and_then(|v| v.as_str()),
                            ) {
                                value_map.insert(name.to_string(), value.to_string());
                            }
                        }

                        // Map results back to original keys
                        secrets
                            .iter()
                            .map(|(key, secret_name)| {
                                let result = value_map.get(secret_name).cloned().ok_or_else(|| {
                                    FnoxError::Provider(format!(
                                        "Secret '{}' not found in batch response",
                                        secret_name
                                    ))
                                });
                                (key.clone(), result)
                            })
                            .collect()
                    }
                    Err(e) => {
                        // JSON parse error - return same error for all secrets
                        let error_msg = format!("Failed to parse Infisical batch response: {}", e);
                        secrets
                            .iter()
                            .map(|(key, _)| {
                                (key.clone(), Err(FnoxError::Provider(error_msg.clone())))
                            })
                            .collect()
                    }
                }
            }
            Err(e) => {
                // CLI error - return same error message for all secrets
                let error_msg = e.to_string();
                secrets
                    .iter()
                    .map(|(key, _)| (key.clone(), Err(FnoxError::Provider(error_msg.clone()))))
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

static INFISICAL_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_INFISICAL_TOKEN")
        .or_else(|_| env::var("INFISICAL_TOKEN"))
        .ok()
});

static INFISICAL_CLIENT_ID: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_INFISICAL_CLIENT_ID")
        .or_else(|_| env::var("INFISICAL_CLIENT_ID"))
        .ok()
});

static INFISICAL_CLIENT_SECRET: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_INFISICAL_CLIENT_SECRET")
        .or_else(|_| env::var("INFISICAL_CLIENT_SECRET"))
        .ok()
});

static INFISICAL_API_URL: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_INFISICAL_API_URL")
        .or_else(|_| env::var("INFISICAL_API_URL"))
        .ok()
});

// Cache login token to avoid repeated login calls
static CACHED_LOGIN_TOKEN: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));
