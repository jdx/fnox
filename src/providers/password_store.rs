use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use async_trait::async_trait;
use std::process::Command;
use std::sync::LazyLock;

/// Provider that integrates with password-store (pass) CLI tool
pub struct PasswordStoreProvider {
    prefix: Option<String>,
    store_dir: Option<String>,
    gpg_opts: Option<String>,
}

impl PasswordStoreProvider {
    pub fn new(
        prefix: Option<String>,
        store_dir: Option<String>,
        gpg_opts: Option<String>,
    ) -> Self {
        Self {
            prefix,
            store_dir,
            gpg_opts,
        }
    }

    /// Build the full secret path with optional prefix
    fn build_secret_path(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{prefix}{key}"),
            None => key.to_string(),
        }
    }

    /// Configure environment variables for pass command
    fn configure_command_env(&self, cmd: &mut Command) {
        // Set custom PASSWORD_STORE_DIR if configured
        let store_dir = self.store_dir.as_deref().or(PASSWORD_STORE_DIR.as_deref());
        if let Some(store_dir) = store_dir {
            cmd.env("PASSWORD_STORE_DIR", store_dir);
        }

        // Set custom GPG options if configured
        let gpg_opts = self
            .gpg_opts
            .as_deref()
            .or(PASSWORD_STORE_GPG_OPTS.as_deref());
        if let Some(gpg_opts) = gpg_opts {
            cmd.env("PASSWORD_STORE_GPG_OPTS", gpg_opts);
        }
    }

    /// Execute pass CLI command
    fn execute_pass_command(&self, args: &[&str]) -> Result<String> {
        tracing::debug!("Executing pass command with args: {args:?}");

        let mut cmd = Command::new("pass");
        self.configure_command_env(&mut cmd);

        cmd.args(args);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "password-store".to_string(),
                    cli: "pass".to_string(),
                    install_hint: "brew install pass".to_string(),
                    url: "https://fnox.jdx.dev/providers/password-store".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "password-store".to_string(),
                    details: e.to_string(),
                    hint: "Check that password-store is installed and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/password-store".to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_str = stderr.trim();
            if stderr_str.contains("not in the password store") {
                return Err(FnoxError::ProviderSecretNotFound {
                    provider: "password-store".to_string(),
                    secret: args.last().copied().unwrap_or("<unspecified>").to_string(),
                    hint: "Check that the secret exists in your password store".to_string(),
                    url: "https://fnox.jdx.dev/providers/password-store".to_string(),
                });
            }
            if stderr_str.contains("gpg") || stderr_str.contains("decrypt") {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "password-store".to_string(),
                    details: stderr_str.to_string(),
                    hint: "Check that your GPG key is available and unlocked".to_string(),
                    url: "https://fnox.jdx.dev/providers/password-store".to_string(),
                });
            }
            return Err(FnoxError::ProviderCliFailed {
                provider: "password-store".to_string(),
                details: stderr_str.to_string(),
                hint: "Check your password-store configuration".to_string(),
                url: "https://fnox.jdx.dev/providers/password-store".to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "password-store".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: "https://fnox.jdx.dev/providers/password-store".to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for PasswordStoreProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let secret_path = self.build_secret_path(value);

        tracing::debug!("Getting secret '{secret_path}' from password-store");

        // Use `pass show` to retrieve the secret
        self.execute_pass_command(&["show", &secret_path])
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let secret_path = self.build_secret_path(key);

        tracing::debug!("Storing secret '{secret_path}' in password-store");

        // Use `pass insert` with multiline support
        // pass insert -m will read from stdin until EOF
        let mut cmd = Command::new("pass");
        self.configure_command_env(&mut cmd);

        cmd.arg("insert")
            .arg("-m") // Multiline
            .arg("-f") // Force (overwrite if exists)
            .arg(&secret_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "password-store".to_string(),
                    cli: "pass".to_string(),
                    install_hint: "brew install pass".to_string(),
                    url: "https://fnox.jdx.dev/providers/password-store".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "password-store".to_string(),
                    details: format!("Failed to spawn 'pass insert': {}", e),
                    hint: "Check that password-store is installed and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/password-store".to_string(),
                }
            }
        })?;

        // Write value to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;

            stdin
                .write_all(value.as_bytes())
                .map_err(|e| FnoxError::ProviderCliFailed {
                    provider: "password-store".to_string(),
                    details: format!("Failed to write to stdin: {}", e),
                    hint: "This is an internal error".to_string(),
                    url: "https://fnox.jdx.dev/providers/password-store".to_string(),
                })?;
            drop(stdin); // Explicitly close stdin to signal EOF
        }

        let output = child
            .wait_with_output()
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: "password-store".to_string(),
                details: format!("Failed to wait for command: {}", e),
                hint: "This is an internal error".to_string(),
                url: "https://fnox.jdx.dev/providers/password-store".to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_str = stderr.trim();
            if stderr_str.contains("gpg") || stderr_str.contains("encrypt") {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "password-store".to_string(),
                    details: stderr_str.to_string(),
                    hint: "Check that your GPG key is available".to_string(),
                    url: "https://fnox.jdx.dev/providers/password-store".to_string(),
                });
            }
            return Err(FnoxError::ProviderCliFailed {
                provider: "password-store".to_string(),
                details: stderr_str.to_string(),
                hint: "Check your password-store configuration".to_string(),
                url: "https://fnox.jdx.dev/providers/password-store".to_string(),
            });
        }

        tracing::debug!("Successfully stored secret '{secret_path}' in password-store");
        Ok(key.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to password-store");

        // Try to list passwords to verify pass is working
        self.execute_pass_command(&["ls"])?;

        tracing::debug!("password-store connection test successful");
        Ok(())
    }
}

static PASSWORD_STORE_DIR: LazyLock<Option<String>> = LazyLock::new(|| {
    std::env::var("FNOX_PASSWORD_STORE_DIR")
        .or_else(|_| std::env::var("PASSWORD_STORE_DIR"))
        .ok()
});

static PASSWORD_STORE_GPG_OPTS: LazyLock<Option<String>> = LazyLock::new(|| {
    std::env::var("FNOX_PASSWORD_STORE_GPG_OPTS")
        .or_else(|_| std::env::var("PASSWORD_STORE_GPG_OPTS"))
        .ok()
});
