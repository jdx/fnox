use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const URL: &str = "https://fnox.jdx.dev/providers/gopass";

/// Provider that integrates with the gopass CLI tool
pub struct GopassProvider {
    mount: Option<String>,
}

impl GopassProvider {
    pub fn new(mount: Option<String>) -> Result<Self> {
        Ok(Self { mount })
    }

    /// Build the full secret path, prefixing the optional mount
    fn build_secret_path(&self, key: &str) -> String {
        match self.mount.as_deref().map(|m| m.trim_matches('/')) {
            Some(mount) if !mount.is_empty() => format!("{mount}/{}", key.trim_start_matches('/')),
            _ => key.to_string(),
        }
    }

    fn cli_error(e: std::io::Error) -> FnoxError {
        if e.kind() == std::io::ErrorKind::NotFound {
            FnoxError::ProviderCliNotFound {
                provider: "gopass".to_string(),
                cli: "gopass".to_string(),
                install_hint: "brew install gopass".to_string(),
                url: URL.to_string(),
            }
        } else {
            FnoxError::ProviderCliFailed {
                provider: "gopass".to_string(),
                details: e.to_string(),
                hint: "Check that gopass is installed and accessible".to_string(),
                url: URL.to_string(),
            }
        }
    }

    fn map_failure(stderr: &str, secret: &str) -> FnoxError {
        let lower = stderr.to_lowercase();
        if lower.contains("not found")
            || lower.contains("entry is not in the password store")
            || lower.contains("no such file")
        {
            return FnoxError::ProviderSecretNotFound {
                provider: "gopass".to_string(),
                secret: secret.to_string(),
                hint: "Check that the secret exists in your gopass store".to_string(),
                url: URL.to_string(),
            };
        }
        if lower.contains("gpg")
            || lower.contains("decrypt")
            || lower.contains("locked")
            || lower.contains("passphrase")
            || lower.contains("agent")
        {
            return FnoxError::ProviderAuthFailed {
                provider: "gopass".to_string(),
                details: stderr.to_string(),
                hint: "Check that your GPG/age key is available and unlocked".to_string(),
                url: URL.to_string(),
            };
        }
        FnoxError::ProviderCliFailed {
            provider: "gopass".to_string(),
            details: stderr.to_string(),
            hint: "Check your gopass configuration".to_string(),
            url: URL.to_string(),
        }
    }

    async fn run(&self, args: &[&str], stdin: Option<&str>, secret: &str) -> Result<String> {
        tracing::debug!("Executing gopass command with args: {args:?}");

        let mut cmd = Command::new("gopass");
        cmd.args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(Self::cli_error)?;

        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(input.as_bytes())
                .await
                .map_err(|e| FnoxError::ProviderCliFailed {
                    provider: "gopass".to_string(),
                    details: format!("Failed to write to stdin: {e}"),
                    hint: "This is an internal error".to_string(),
                    url: URL.to_string(),
                })?;
            drop(pipe);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: "gopass".to_string(),
                details: format!("Failed to wait for command: {e}"),
                hint: "This is an internal error".to_string(),
                url: URL.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Self::map_failure(stderr.trim(), secret));
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "gopass".to_string(),
                details: format!("Invalid UTF-8 in command output: {e}"),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: URL.to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for GopassProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let path = self.build_secret_path(value);
        tracing::debug!("Getting secret '{path}' from gopass");
        // `cat` prints the raw secret content without clipboard or parsing side effects
        self.run(&["cat", &path], None, &path).await
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let path = self.build_secret_path(key);
        tracing::debug!("Storing secret '{path}' in gopass");
        // Non-interactive stdin is read as the full secret; -f overwrites
        self.run(&["insert", "-f", &path], Some(value), &path)
            .await?;
        Ok(key.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to gopass");
        self.run(&["ls", "--flat"], None, "<store>").await?;
        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &["GNUPGHOME", "GOPASS_HOMEDIR", "GOPASS_CONFIG_NOWRAP"]
}
