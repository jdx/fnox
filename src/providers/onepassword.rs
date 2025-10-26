use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::process::Command;
use std::{path::Path, sync::LazyLock};

pub struct OnePasswordProvider {
    vault: Option<String>,
    account: Option<String>,
}

impl OnePasswordProvider {
    pub fn new(vault: Option<String>, account: Option<String>) -> Self {
        Self { vault, account }
    }

    /// Execute op CLI command with proper authentication
    fn execute_op_command(&self, args: &[&str]) -> Result<String> {
        tracing::debug!("Executing op command with args: {:?}", args);

        let mut cmd = Command::new("op");
        if let Some(token) = &*OP_SERVICE_ACCOUNT_TOKEN {
            tracing::debug!(
                "Setting OP_SERVICE_ACCOUNT_TOKEN from LazyLock (token length: {})",
                token.len()
            );
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
        } else {
            tracing::warn!("OP_SERVICE_ACCOUNT_TOKEN not found in environment");
        }
        cmd.args(args);

        // The OP_SERVICE_ACCOUNT_TOKEN environment variable should be set externally
        // Users should run: export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
        // The op CLI will automatically use this environment variable

        // Add account flag if specified
        if let Some(account) = &self.account {
            cmd.arg("--account").arg(account);
        }

        let output = cmd.output().map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to execute 'op' command: {}. Make sure the 1Password CLI is installed.",
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::Provider(format!(
                "1Password CLI command failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for OnePasswordProvider {
    async fn get_secret(&self, value: &str, _key_file: Option<&Path>) -> Result<String> {
        tracing::debug!("Getting secret '{}' from 1Password", value);

        // Check if value is already a full op:// reference
        let reference = if value.starts_with("op://") {
            value.to_string()
        } else if self.vault.is_none() {
            return Err(FnoxError::Provider(format!(
                "Unknown secret vault for: '{}'. Expected value starting with 'op://' or a vault specified in the provider configuration.",
                value
            )));
        } else {
            // Parse value as "item/field" or just "item"
            // Default field is "password" if not specified
            let parts: Vec<&str> = value.split('/').collect();
            match parts.len() {
                1 => format!(
                    "op://{}/{}/password",
                    self.vault.as_ref().unwrap(),
                    parts[0]
                ),
                2 => format!(
                    "op://{}/{}/{}",
                    self.vault.as_ref().unwrap(),
                    parts[0],
                    parts[1]
                ),
                _ => {
                    return Err(FnoxError::Provider(format!(
                        "Invalid secret reference format: '{}'. Expected 'item' or 'item/field'",
                        value
                    )));
                }
            }
        };

        tracing::debug!("Reading 1Password secret: {}", reference);

        // Use 'op read' to fetch the secret
        self.execute_op_command(&["read", &reference])
    }
}

static OP_SERVICE_ACCOUNT_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_OP_SERVICE_ACCOUNT_TOKEN")
        .or_else(|_| env::var("OP_SERVICE_ACCOUNT_TOKEN"))
        .ok()
});
