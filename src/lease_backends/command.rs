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
}

impl CommandBackend {
    pub fn new(create_command: String, revoke_command: Option<String>) -> Self {
        Self {
            create_command,
            revoke_command,
        }
    }
}

#[async_trait]
impl LeaseBackend for CommandBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(&self.create_command)
            .env("FNOX_LEASE_DURATION", duration.as_secs().to_string())
            .env("FNOX_LEASE_LABEL", label)
            .output()
            .await
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: "Command".to_string(),
                details: e.to_string(),
                hint: format!("Failed to execute create_command: {}", self.create_command),
                url: URL.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::ProviderCliFailed {
                provider: "Command".to_string(),
                details: stderr.trim().to_string(),
                hint: format!("create_command exited with {}", output.status),
                url: URL.to_string(),
            });
        }

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
            }
        }

        let expires_at = parsed["expires_at"].as_str().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
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

        let output = Command::new("sh")
            .arg("-c")
            .arg(revoke_cmd)
            .env("FNOX_LEASE_ID", lease_id)
            .output()
            .await
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: "Command".to_string(),
                details: e.to_string(),
                hint: format!("Failed to execute revoke_command: {}", revoke_cmd),
                url: URL.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::ProviderCliFailed {
                provider: "Command".to_string(),
                details: stderr.trim().to_string(),
                hint: format!("revoke_command exited with {}", output.status),
                url: URL.to_string(),
            });
        }

        Ok(())
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(24 * 3600)
    }
}
