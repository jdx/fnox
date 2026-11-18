use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const URL: &str = "https://fnox.jdx.dev/providers/passage";

/// Provider that integrates with passage, the age-based fork of pass
pub struct PassageProvider {
    prefix: Option<String>,
    store_dir: Option<String>,
    identities_file: Option<String>,
}

impl PassageProvider {
    pub fn new(
        prefix: Option<String>,
        store_dir: Option<String>,
        identities_file: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            prefix,
            store_dir,
            identities_file,
        })
    }

    /// Build the full secret path with optional prefix
    fn build_secret_path(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{prefix}{key}"),
            None => key.to_string(),
        }
    }

    /// Configure environment variables for the passage command
    fn configure_command_env(&self, cmd: &mut Command) {
        let env_store_dir = env::passage_dir();
        if let Some(dir) = self.store_dir.as_deref().or(env_store_dir.as_deref()) {
            cmd.env("PASSAGE_DIR", dir);
        }
        let env_identities = env::passage_identities_file();
        if let Some(file) = self
            .identities_file
            .as_deref()
            .or(env_identities.as_deref())
        {
            cmd.env("PASSAGE_IDENTITIES_FILE", file);
        }
    }

    fn cli_error(e: std::io::Error) -> FnoxError {
        if e.kind() == std::io::ErrorKind::NotFound {
            FnoxError::ProviderCliNotFound {
                provider: "passage".to_string(),
                cli: "passage".to_string(),
                install_hint: "see https://github.com/FiloSottile/passage for install steps"
                    .to_string(),
                url: URL.to_string(),
            }
        } else {
            FnoxError::ProviderCliFailed {
                provider: "passage".to_string(),
                details: e.to_string(),
                hint: "Check that passage is installed and accessible".to_string(),
                url: URL.to_string(),
            }
        }
    }

    fn map_failure(stderr: &str, secret: &str) -> FnoxError {
        let lower = stderr.to_lowercase();
        if lower.contains("is not in the password store") {
            return FnoxError::ProviderSecretNotFound {
                provider: "passage".to_string(),
                secret: secret.to_string(),
                hint: "Check that the secret exists in your passage store".to_string(),
                url: URL.to_string(),
            };
        }
        if lower.contains("identit")
            || lower.contains("decrypt")
            || lower.contains("passphrase")
            || lower.contains("no identity matched")
            || lower.contains("recipient")
        {
            return FnoxError::ProviderAuthFailed {
                provider: "passage".to_string(),
                details: stderr.to_string(),
                hint:
                    "Check that your age identity file exists and matches a recipient of the store"
                        .to_string(),
                url: URL.to_string(),
            };
        }
        FnoxError::ProviderCliFailed {
            provider: "passage".to_string(),
            details: stderr.to_string(),
            hint: "Check your passage configuration".to_string(),
            url: URL.to_string(),
        }
    }

    async fn run(&self, args: &[&str], stdin: Option<&str>, secret: &str) -> Result<String> {
        tracing::debug!("Executing passage command with args: {args:?}");

        let mut cmd = Command::new("passage");
        self.configure_command_env(&mut cmd);
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
                    provider: "passage".to_string(),
                    details: format!("Failed to write to stdin: {e}"),
                    hint: "This is an internal error".to_string(),
                    url: URL.to_string(),
                })?;
            drop(pipe);
        }

        // Forward stderr to the terminal as it arrives while also keeping it for error
        // mapping. age plugins (YubiKey, etc.) print touch and PIN prompts there, and
        // holding them until exit would make a hardware identity look like a hang.
        let stderr_pipe = child.stderr.take();
        let stderr_task = tokio::spawn(async move {
            let mut captured = Vec::new();
            if let Some(pipe) = stderr_pipe {
                let mut reader = tokio::io::BufReader::new(pipe);
                let mut term = tokio::io::stderr();
                let mut line = Vec::new();
                loop {
                    line.clear();
                    match reader.read_until(b'\n', &mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    captured.extend_from_slice(&line);
                    // passage's own "Error: ..." lines are left for the caller to report
                    // (or suppress, as with `if_missing = "ignore"`); everything else is
                    // a prompt or plugin message the user needs to see now.
                    if !env::is_non_interactive() && !line.starts_with(b"Error:") {
                        let _ = term.write_all(&line).await;
                        let _ = term.flush().await;
                    }
                }
            }
            captured
        });

        let mut stdout_pipe = child.stdout.take();
        let stdout_task = tokio::spawn(async move {
            let mut out = Vec::new();
            if let Some(pipe) = stdout_pipe.as_mut() {
                let _ = pipe.read_to_end(&mut out).await;
            }
            out
        });

        let status = child
            .wait()
            .await
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: "passage".to_string(),
                details: format!("Failed to wait for command: {e}"),
                hint: "This is an internal error".to_string(),
                url: URL.to_string(),
            })?;
        let stderr_bytes = stderr_task.await.unwrap_or_default();
        let stdout_bytes = stdout_task.await.unwrap_or_default();

        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr_bytes);
            return Err(Self::map_failure(stderr.trim(), secret));
        }

        let stdout =
            String::from_utf8(stdout_bytes).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "passage".to_string(),
                details: format!("Invalid UTF-8 in command output: {e}"),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: URL.to_string(),
            })?;

        // `passage show` reproduces the decrypted bytes exactly (it round-trips them through
        // base64), so the output is the stored value with nothing added; return it unchanged.
        Ok(stdout)
    }
}

#[async_trait]
impl crate::providers::Provider for PassageProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let path = self.build_secret_path(value);
        tracing::debug!("Getting secret '{path}' from passage");
        self.run(&["show", &path], None, &path).await
    }

    /// Read secrets one at a time: age has no agent, so each `passage show` may prompt for a
    /// passphrase or hardware tap on the terminal, and concurrent prompts would collide.
    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let mut results = HashMap::with_capacity(secrets.len());
        for (key, value) in secrets {
            results.insert(key.clone(), self.get_secret(value).await);
        }
        results
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let path = self.build_secret_path(key);
        tracing::debug!("Storing secret '{path}' in passage");
        // -m reads the full multi-line value from stdin until EOF; -f overwrites
        self.run(&["insert", "-m", "-f", &path], Some(value), &path)
            .await?;
        Ok(key.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to passage");
        self.run(&["ls"], None, "<store>").await?;
        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &[
        "PASSAGE_DIR",
        "FNOX_PASSAGE_DIR",
        "PASSAGE_IDENTITIES_FILE",
        "FNOX_PASSAGE_IDENTITIES_FILE",
    ]
}
