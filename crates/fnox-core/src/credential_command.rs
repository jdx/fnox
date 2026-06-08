use crate::error::{FnoxError, Result};
use serde_json::Value;
use std::time::Duration;
use tera::{Context, Tera};
use tokio::process::Command;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn run(
    provider: &str,
    command: &str,
    context: Value,
    envs: &[(&str, String)],
    timeout: Duration,
    url: &str,
) -> Result<String> {
    let tera_context =
        Context::from_value(context).map_err(|e| FnoxError::Config(e.to_string()))?;
    let rendered =
        Tera::one_off(command, &tera_context, false).map_err(|e| FnoxError::ProviderCliFailed {
            provider: provider.to_string(),
            details: format!("Failed to render credential_command: {e}"),
            hint: "Check credential_command template syntax".to_string(),
            url: url.to_string(),
        })?;

    tracing::debug!("Running credential_command for {provider}");

    let mut cmd = shell_command(&rendered);
    for (key, value) in envs {
        cmd.env(key, value);
    }

    let output = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| FnoxError::ProviderCliFailed {
            provider: provider.to_string(),
            details: format!("credential_command timed out after {}s", timeout.as_secs()),
            hint: "Check that credential_command completes in time".to_string(),
            url: url.to_string(),
        })?
        .map_err(|e| FnoxError::ProviderCliFailed {
            provider: provider.to_string(),
            details: e.to_string(),
            hint: "Failed to execute credential_command".to_string(),
            url: url.to_string(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FnoxError::ProviderCliFailed {
            provider: provider.to_string(),
            details: stderr.trim().to_string(),
            hint: format!("credential_command exited with {}", output.status),
            url: url.to_string(),
        });
    }

    let stdout =
        String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: provider.to_string(),
            details: format!("Invalid UTF-8 in credential_command output: {e}"),
            hint: "credential_command must output a UTF-8 token".to_string(),
            url: url.to_string(),
        })?;
    let token = stdout.trim().to_string();
    if token.is_empty() {
        return Err(FnoxError::ProviderInvalidResponse {
            provider: provider.to_string(),
            details: "credential_command returned empty stdout".to_string(),
            hint: "Ensure credential_command prints the token to stdout".to_string(),
            url: url.to_string(),
        });
    }

    Ok(token)
}

fn shell_command(command: &str) -> Command {
    if cfg!(target_os = "windows") {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", command]);
        cmd
    } else {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", command]);
        cmd
    }
}
