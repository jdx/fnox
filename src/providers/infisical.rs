use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::process::Command;
use std::{path::Path, sync::LazyLock};

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

    /// Execute infisical CLI command with proper authentication
    fn execute_infisical_command(&self, args: &[&str]) -> Result<String> {
        tracing::debug!("Executing infisical command with args: {:?}", args);

        let mut cmd = Command::new("infisical");

        // Check if token is available
        if let Some(token) = &*INFISICAL_TOKEN {
            tracing::debug!(
                "Found INFISICAL_TOKEN in environment (length: {})",
                token.len()
            );
            cmd.env("INFISICAL_TOKEN", token);
        } else {
            // INFISICAL_TOKEN not found - this will cause infisical to fail
            tracing::error!(
                "INFISICAL_TOKEN not found in environment. Set INFISICAL_TOKEN or FNOX_INFISICAL_TOKEN"
            );
            return Err(FnoxError::Provider(
                "Infisical token not found. Please set INFISICAL_TOKEN environment variable:\n  \
                 export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)\n\
                 Or set FNOX_INFISICAL_TOKEN in your configuration."
                    .to_string(),
            ));
        }

        cmd.args(args);

        // Close stdin to prevent infisical from prompting interactively
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

        // Build the infisical secrets get command
        // infisical secrets get <secret-name> [flags]
        let mut args = vec!["secrets", "get", value, "--plain"];

        // Collect additional arguments as Strings to extend their lifetime
        let mut additional_args = Vec::new();

        // Add project ID if specified
        if let Some(project_id) = &self.project_id {
            additional_args.push("--projectId".to_string());
            additional_args.push(project_id.clone());
        }

        // Add environment if specified
        if let Some(environment) = &self.environment {
            additional_args.push("--env".to_string());
            additional_args.push(environment.clone());
        }

        // Add path if specified
        if let Some(path) = &self.path {
            additional_args.push("--path".to_string());
            additional_args.push(path.clone());
        }

        // Convert additional_args to &str references
        for arg in &additional_args {
            args.push(arg.as_str());
        }

        tracing::debug!("Reading Infisical secret '{}' with args: {:?}", value, args);

        self.execute_infisical_command(&args)
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Infisical");

        // Try to execute a simple command to verify authentication
        let args = vec!["user"];

        // The user command should work with just a token
        self.execute_infisical_command(&args)?;

        tracing::debug!("Infisical connection test successful");

        Ok(())
    }
}

static INFISICAL_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_INFISICAL_TOKEN")
        .or_else(|_| env::var("INFISICAL_TOKEN"))
        .ok()
});
