use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::process::Command;

const URL: &str = "https://fnox.jdx.dev/providers/bitwarden-sm";

pub fn env_dependencies() -> &'static [&'static str] {
    &["BWS_ACCESS_TOKEN", "FNOX_BWS_ACCESS_TOKEN"]
}

pub struct BitwardenSecretsManagerProvider {
    project_id: String,
    profile: Option<String>,
}

impl BitwardenSecretsManagerProvider {
    pub fn new(project_id: String, profile: Option<String>) -> Self {
        Self {
            project_id,
            profile,
        }
    }

    fn get_access_token() -> Result<String> {
        bws_access_token().ok_or_else(|| FnoxError::ProviderAuthFailed {
            provider: "Bitwarden Secrets Manager".to_string(),
            details: "Access token not found".to_string(),
            hint: "Set BWS_ACCESS_TOKEN or FNOX_BWS_ACCESS_TOKEN".to_string(),
            url: URL.to_string(),
        })
    }

    fn execute_bws_command(&self, args: &[&str]) -> Result<String> {
        tracing::debug!("Executing bws command with args: {:?}", args);

        let token = Self::get_access_token()?;

        let mut cmd = Command::new("bws");
        cmd.env("BWS_ACCESS_TOKEN", &token);
        cmd.stdin(std::process::Stdio::null());

        if let Some(profile) = &self.profile {
            cmd.args(["--profile", profile]);
        }

        cmd.args(args);

        let output = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "Bitwarden Secrets Manager".to_string(),
                    cli: "bws".to_string(),
                    install_hint: "brew install bws".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "Bitwarden Secrets Manager".to_string(),
                    details: e.to_string(),
                    hint: "Check that bws is installed and accessible".to_string(),
                    url: URL.to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_str = stderr.trim();

            if stderr_str.contains("Unauthorized")
                || stderr_str.contains("unauthorized")
                || stderr_str.contains("access token")
                || stderr_str.contains("Access token")
                || stderr_str.contains("authentication")
                || stderr_str.contains("Authentication")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Bitwarden Secrets Manager".to_string(),
                    details: stderr_str.to_string(),
                    hint: "Check your BWS_ACCESS_TOKEN is valid".to_string(),
                    url: URL.to_string(),
                });
            }

            if stderr_str.contains("not found")
                || stderr_str.contains("Not found")
                || stderr_str.contains("NotFound")
            {
                return Err(FnoxError::ProviderSecretNotFound {
                    provider: "Bitwarden Secrets Manager".to_string(),
                    secret: args.last().unwrap_or(&"unknown").to_string(),
                    hint: "Check that the secret ID exists in Bitwarden Secrets Manager"
                        .to_string(),
                    url: URL.to_string(),
                });
            }

            return Err(FnoxError::ProviderCliFailed {
                provider: "Bitwarden Secrets Manager".to_string(),
                details: stderr_str.to_string(),
                hint: "Check your Bitwarden Secrets Manager configuration".to_string(),
                url: URL.to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden Secrets Manager".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: URL.to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }

    fn parse_secret_json(json_str: &str, field: &str) -> Result<String> {
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden Secrets Manager".to_string(),
                details: format!("Failed to parse JSON: {}", e),
                hint: "Unexpected response from bws CLI".to_string(),
                url: URL.to_string(),
            })?;

        parsed[field]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden Secrets Manager".to_string(),
                details: format!("Field '{}' not found in secret JSON", field),
                hint: "Supported fields: value, key, note".to_string(),
                url: URL.to_string(),
            })
    }
}

#[async_trait]
impl crate::providers::Provider for BitwardenSecretsManagerProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!(
            "Getting secret '{}' from Bitwarden Secrets Manager",
            value
        );

        // Parse value as "<secret_id>" or "<secret_id>/field"
        // Default field is "value" if not specified
        let parts: Vec<&str> = value.split('/').collect();

        let (secret_id, field_name) = match parts.len() {
            1 => (parts[0], "value"),
            2 => (parts[0], parts[1]),
            _ => {
                return Err(FnoxError::ProviderInvalidResponse {
                    provider: "Bitwarden Secrets Manager".to_string(),
                    details: format!("Invalid secret reference format: '{}'", value),
                    hint: "Expected '<secret_id>' or '<secret_id>/field' (fields: value, key, note)".to_string(),
                    url: URL.to_string(),
                });
            }
        };

        // Validate field name before making the API call
        if !matches!(field_name, "value" | "key" | "note") {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden Secrets Manager".to_string(),
                details: format!("Unknown field '{}' in secret reference", field_name),
                hint: "Supported fields: value, key, note".to_string(),
                url: URL.to_string(),
            });
        }

        tracing::debug!(
            "Reading BSM secret '{}' field '{}'",
            secret_id,
            field_name
        );

        let json_output =
            self.execute_bws_command(&["secret", "get", secret_id, "--output", "json"])?;
        Self::parse_secret_json(&json_output, field_name)
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        // Try editing as an existing secret (key is a UUID) first,
        // fall back to creating a new secret if that fails
        tracing::debug!("Attempting to edit BSM secret '{}'", key);
        match self.execute_bws_command(&["secret", "edit", key, "--value", value]) {
            Ok(_) => Ok(key.to_string()),
            Err(_) => {
                tracing::debug!(
                    "Edit failed, creating new BSM secret '{}' in project '{}'",
                    key,
                    self.project_id
                );
                let json_output = self.execute_bws_command(&[
                    "secret",
                    "create",
                    key,
                    value,
                    &self.project_id,
                    "--output",
                    "json",
                ])?;

                // Return the new secret's UUID so it can be stored in config
                Self::parse_secret_json(&json_output, "id")
            }
        }
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Bitwarden Secrets Manager");
        self.execute_bws_command(&["project", "list", "--output", "json"])?;
        Ok(())
    }
}

fn bws_access_token() -> Option<String> {
    env::var("FNOX_BWS_ACCESS_TOKEN")
        .or_else(|_| env::var("BWS_ACCESS_TOKEN"))
        .ok()
}
