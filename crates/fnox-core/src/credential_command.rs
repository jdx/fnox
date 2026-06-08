use crate::error::{FnoxError, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tera::{Context, Tera};
use tokio::process::Command;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

static CACHE: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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

    let cache_key = cache_key(provider, &rendered, envs);
    if let Some(token) = CACHE
        .lock()
        .expect("credential cache lock poisoned")
        .get(&cache_key)
    {
        tracing::debug!("Using cached credential_command output for {provider}");
        return Ok(token.clone());
    }

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

    CACHE
        .lock()
        .expect("credential cache lock poisoned")
        .insert(cache_key, token.clone());

    Ok(token)
}

fn cache_key(provider: &str, command: &str, envs: &[(&str, String)]) -> String {
    let mut envs = envs.to_vec();
    envs.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(&b.1)));

    let mut hasher = blake3::Hasher::new();
    hasher.update(provider.as_bytes());
    hasher.update(b"\0");
    hasher.update(command.as_bytes());
    for (key, value) in envs {
        hasher.update(b"\0");
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn shell_command(command: &str) -> Command {
    // `cfg!` selects the shell for the target binary at compile time, which
    // matches fnox's native build/release flow. Cross-compiled artifacts should
    // be built per target so Windows binaries use cmd and Unix binaries use sh.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn credential_command_output_is_cached() {
        let tempdir = tempfile::tempdir().unwrap();
        let count_file = tempdir.path().join("count");
        let count_path = count_file.display();
        let command = format!(
            "count=$(cat '{count_path}' 2>/dev/null || echo 0); count=$((count + 1)); printf '%s' \"$count\" > '{count_path}'; printf token"
        );

        let first = run(
            "Test",
            &command,
            json!({}),
            &[("VAULT_ADDR", "https://vault.example.com".to_string())],
            DEFAULT_TIMEOUT,
            "https://example.com",
        )
        .await
        .unwrap();
        let second = run(
            "Test",
            &command,
            json!({}),
            &[("VAULT_ADDR", "https://vault.example.com".to_string())],
            DEFAULT_TIMEOUT,
            "https://example.com",
        )
        .await
        .unwrap();

        assert_eq!(first, "token");
        assert_eq!(second, "token");
        assert_eq!(std::fs::read_to_string(count_file).unwrap(), "1");
    }
}
