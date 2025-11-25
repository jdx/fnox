use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use async_trait::async_trait;
use std::path::Path;
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
            FnoxError::Provider(format!(
                "Failed to execute 'pass' command: {e}. Make sure password-store is installed."
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::Provider(format!(
                "password-store CLI command failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {e}")))?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for PasswordStoreProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str, _key_file: Option<&Path>) -> Result<String> {
        let secret_path = self.build_secret_path(value);

        tracing::debug!("Getting secret '{secret_path}' from password-store");

        // Use `pass show` to retrieve the secret
        self.execute_pass_command(&["show", &secret_path])
    }

    async fn put_secret(&self, key: &str, value: &str, _key_file: Option<&Path>) -> Result<String> {
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
            FnoxError::Provider(format!("Failed to spawn 'pass insert' command: {e}"))
        })?;

        // Write value to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;

            stdin.write_all(value.as_bytes()).map_err(|e| {
                FnoxError::Provider(format!("Failed to write to 'pass insert' stdin: {e}"))
            })?;
            drop(stdin); // Explicitly close stdin to signal EOF
        }

        let output = child.wait_with_output().map_err(|e| {
            FnoxError::Provider(format!("Failed to wait for 'pass insert' command: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::Provider(format!(
                "Failed to store secret in password-store: {}",
                stderr.trim()
            )));
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
