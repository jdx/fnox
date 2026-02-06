use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::process::Command;

const URL: &str = "https://fnox.jdx.dev/providers/bitwarden-sm";

pub fn env_dependencies() -> &'static [&'static str] {
    &["FNOX_BWS_ACCESS_TOKEN", "BWS_ACCESS_TOKEN"]
}

pub struct BitwardenSecretsManagerProvider {
    project_id: Option<String>,
    profile: Option<String>,
}

impl BitwardenSecretsManagerProvider {
    pub fn new(project_id: Option<String>, profile: Option<String>) -> Self {
        Self {
            project_id,
            profile,
        }
    }

    fn resolve_project_id(&self) -> Result<String> {
        self.project_id
            .clone()
            .or_else(|| env::var("BWS_PROJECT_ID").ok())
            .ok_or_else(|| FnoxError::ProviderCliFailed {
                provider: "Bitwarden Secrets Manager".to_string(),
                details: "Project ID not configured".to_string(),
                hint: "Set project_id in provider config or BWS_PROJECT_ID env var".to_string(),
                url: URL.to_string(),
            })
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

            let stderr_lower = stderr_str.to_lowercase();
            if stderr_lower.contains("unauthorized")
                || stderr_lower.contains("access token")
                || stderr_lower.contains("authentication")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Bitwarden Secrets Manager".to_string(),
                    details: stderr_str.to_string(),
                    hint: "Check your BWS_ACCESS_TOKEN is valid".to_string(),
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

    fn find_secret_by_key<'a>(
        secrets: &'a [serde_json::Value],
        key: &str,
    ) -> Result<&'a serde_json::Value> {
        secrets
            .iter()
            .find(|s| s["key"].as_str() == Some(key))
            .ok_or_else(|| FnoxError::ProviderSecretNotFound {
                provider: "Bitwarden Secrets Manager".to_string(),
                secret: key.to_string(),
                hint: "Check that the secret name exists in the project".to_string(),
                url: URL.to_string(),
            })
    }

    fn list_secrets(&self) -> Result<Vec<serde_json::Value>> {
        let project_id = self.resolve_project_id()?;
        let json_output =
            self.execute_bws_command(&["secret", "list", &project_id, "--output", "json"])?;

        serde_json::from_str(&json_output).map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: "Bitwarden Secrets Manager".to_string(),
            details: format!("Failed to parse JSON: {}", e),
            hint: "Unexpected response from bws CLI".to_string(),
            url: URL.to_string(),
        })
    }

    fn resolve_reference(secrets: &[serde_json::Value], value: &str) -> Result<String> {
        let (key_name, field_name) = match value.split_once('/') {
            None => (value, "value"),
            Some((name, field)) => (name, field),
        };

        if !matches!(field_name, "value" | "key" | "note") {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden Secrets Manager".to_string(),
                details: format!("Unknown field '{}' in secret reference", field_name),
                hint: "Supported fields: value, key, note".to_string(),
                url: URL.to_string(),
            });
        }

        let secret = Self::find_secret_by_key(secrets, key_name)?;

        secret[field_name]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden Secrets Manager".to_string(),
                details: format!("Field '{}' not found in secret", field_name),
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
        tracing::debug!("Getting secret '{}' from Bitwarden Secrets Manager", value);
        let secrets = self.list_secrets()?;
        Self::resolve_reference(&secrets, value)
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        if secrets.is_empty() {
            return HashMap::new();
        }

        tracing::debug!(
            "Batch fetching {} secrets from Bitwarden Secrets Manager",
            secrets.len()
        );

        // Single list call for all secrets
        let all_secrets = match self.list_secrets() {
            Ok(s) => s,
            Err(e) => {
                // Return the same error for all secrets
                return secrets
                    .iter()
                    .map(|(key, _)| {
                        (
                            key.clone(),
                            Err(FnoxError::ProviderCliFailed {
                                provider: "Bitwarden Secrets Manager".to_string(),
                                details: e.to_string(),
                                hint: "Check your Bitwarden Secrets Manager configuration"
                                    .to_string(),
                                url: URL.to_string(),
                            }),
                        )
                    })
                    .collect();
            }
        };

        // Resolve each secret from the single listing
        secrets
            .iter()
            .map(|(key, value)| {
                let result = Self::resolve_reference(&all_secrets, value);
                (key.clone(), result)
            })
            .collect()
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let secrets = self.list_secrets()?;

        if let Some(existing) = secrets.iter().find(|s| s["key"].as_str() == Some(key)) {
            // Update existing secret by its UUID
            let id = existing["id"]
                .as_str()
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: "Bitwarden Secrets Manager".to_string(),
                    details: "Secret missing 'id' field".to_string(),
                    hint: "Unexpected response from bws CLI".to_string(),
                    url: URL.to_string(),
                })?;
            tracing::debug!("Editing existing BSM secret '{}' ({})", key, id);
            self.execute_bws_command(&["secret", "edit", id, "--value", value])?;
        } else {
            let project_id = self.resolve_project_id()?;
            tracing::debug!(
                "Creating new BSM secret '{}' in project '{}'",
                key,
                project_id
            );
            self.execute_bws_command(&["secret", "create", key, value, &project_id])?;
        }

        // Return the key name to store in config
        Ok(key.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Bitwarden Secrets Manager");
        self.list_secrets()?;
        Ok(())
    }
}

fn bws_access_token() -> Option<String> {
    env::var("FNOX_BWS_ACCESS_TOKEN")
        .or_else(|_| env::var("BWS_ACCESS_TOKEN"))
        .ok()
}
