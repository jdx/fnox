use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::time::Duration;
use tokio::process::Command;

const URL: &str = "https://fnox.jdx.dev/leases/command";

pub struct CommandBackend {
    create_command: String,
    revoke_command: Option<String>,
    timeout: Duration,
}

impl CommandBackend {
    pub fn new(create_command: String, revoke_command: Option<String>, timeout: Duration) -> Self {
        Self {
            create_command,
            revoke_command,
            timeout,
        }
    }

    async fn run_command(
        &self,
        cmd_str: &str,
        envs: &[(&str, String)],
        action: &str,
    ) -> Result<std::process::Output> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(cmd_str);
        for (k, v) in envs {
            cmd.env(k, v);
        }

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .map_err(|_| FnoxError::ProviderCliFailed {
                provider: "Command".to_string(),
                details: format!("{} timed out after {}s", action, self.timeout.as_secs()),
                hint: format!(
                    "Check that '{}' completes in time, or increase the timeout",
                    cmd_str
                ),
                url: URL.to_string(),
            })?
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: "Command".to_string(),
                details: e.to_string(),
                hint: format!("Failed to execute {}: {}", action, cmd_str),
                url: URL.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::ProviderCliFailed {
                provider: "Command".to_string(),
                details: stderr.trim().to_string(),
                hint: format!("{} exited with {}", action, output.status),
                url: URL.to_string(),
            });
        }

        Ok(output)
    }
}

#[async_trait]
impl LeaseBackend for CommandBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let output = self
            .run_command(
                &self.create_command,
                &[
                    ("FNOX_LEASE_DURATION", duration.as_secs().to_string()),
                    ("FNOX_LEASE_LABEL", label.to_string()),
                ],
                "create_command",
            )
            .await?;

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Command".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "Command must output valid UTF-8 JSON".to_string(),
                url: URL.to_string(),
            })?;

        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Command".to_string(),
                details: format!("Invalid JSON output: {}", e),
                hint: "Command must output JSON with a 'credentials' object".to_string(),
                url: URL.to_string(),
            })?;

        let creds_obj = parsed["credentials"].as_object().ok_or_else(|| {
            FnoxError::ProviderInvalidResponse {
                provider: "Command".to_string(),
                details: "Output missing 'credentials' object".to_string(),
                hint: "Command must output JSON: { \"credentials\": { \"KEY\": \"value\" } }"
                    .to_string(),
                url: URL.to_string(),
            }
        })?;

        let mut credentials = IndexMap::new();
        for (key, value) in creds_obj {
            if let Some(v) = value.as_str() {
                credentials.insert(key.clone(), v.to_string());
            } else {
                tracing::warn!(
                    "Command backend: credential '{}' is not a string, skipping",
                    key
                );
            }
        }
        if credentials.is_empty() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "Command".to_string(),
                details: "Command returned an empty 'credentials' object".to_string(),
                hint: "Ensure the command outputs at least one string credential".to_string(),
                url: URL.to_string(),
            });
        }

        let expires_at = parsed["expires_at"].as_str().and_then(|s| {
            match chrono::DateTime::parse_from_rfc3339(s) {
                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                Err(e) => {
                    tracing::warn!(
                        "Command backend: could not parse expires_at {:?}: {}; lease treated as non-expiring",
                        s, e
                    );
                    None
                }
            }
        });

        let lease_id = parsed["lease_id"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("cmd-{}", chrono::Utc::now().timestamp_millis()));

        Ok(Lease {
            credentials,
            expires_at,
            lease_id,
        })
    }

    async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        let Some(revoke_cmd) = &self.revoke_command else {
            return Ok(());
        };

        self.run_command(
            revoke_cmd,
            &[("FNOX_LEASE_ID", lease_id.to_string())],
            "revoke_command",
        )
        .await?;

        Ok(())
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(24 * 3600)
    }
}
