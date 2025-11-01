use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::path::Path;
use std::process::Command;
use std::sync::{LazyLock, Mutex};

pub struct InfisicalProvider {
    project_id: String,
    environment: String,
    path: String,
}

impl InfisicalProvider {
    pub fn new(
        project_id: Option<String>,
        environment: Option<String>,
        path: Option<String>,
    ) -> Self {
        Self {
            project_id: project_id.unwrap_or_default(),
            environment: environment.unwrap_or_else(|| "dev".to_string()),
            path: path.unwrap_or_else(|| "/".to_string()),
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

        // Check if we have a cached token
        let cached_token = CACHED_LOGIN_TOKEN.lock().unwrap();
        if let Some(token) = cached_token.as_ref() {
            tracing::debug!("Using cached login token");
            return Ok(token.clone());
        }
        drop(cached_token);

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

        // Add custom API URL if specified
        if let Some(api_url) = &*INFISICAL_API_URL {
            cmd.arg("--domain");
            cmd.arg(api_url);
            tracing::debug!("Using custom Infisical API URL: {}", api_url);
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

        // Cache the token for subsequent calls
        let mut cached_token = CACHED_LOGIN_TOKEN.lock().unwrap();
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

        // Add custom API URL if specified
        if let Some(api_url) = &*INFISICAL_API_URL {
            cmd.arg("--domain");
            cmd.arg(api_url);
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

        // Validate that project_id is set
        if self.project_id.is_empty() {
            return Err(FnoxError::Provider(
                "Infisical project_id is required but not configured. Please add 'project_id' to your provider configuration.".to_string()
            ));
        }

        // Build the command: infisical secrets get <name>
        let mut args = vec!["secrets", "get", value, "--plain"];

        // Add project ID
        let project_arg = format!("--projectId={}", self.project_id);
        args.push(&project_arg);

        // Add environment (global flag)
        let env_arg = format!("--env={}", self.environment);
        args.push(&env_arg);

        // Add path if not default
        let path_arg;
        if self.path != "/" {
            path_arg = format!("--path={}", self.path);
            args.push(&path_arg);
        }

        tracing::debug!(
            "Fetching secret '{}' from project '{}', environment '{}', path '{}'",
            value,
            self.project_id,
            self.environment,
            self.path
        );

        self.execute_infisical_command(&args)
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
