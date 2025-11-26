use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::LazyLock;

/// Precompiled regex to remove leading error prefixes from stderr output of `op`.
/// [ERROR] YYYY/MM/DD HH:MM:SS message
static ERROR_PREFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\[ERROR\] \d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ").unwrap());

pub struct OnePasswordProvider {
    vault: Option<String>,
    account: Option<String>,
}

impl OnePasswordProvider {
    pub fn new(vault: Option<String>, account: Option<String>) -> Self {
        Self { vault, account }
    }

    /// Convert a value to an op:// reference
    fn value_to_reference(&self, value: &str) -> Result<String> {
        // Check if value is already a full op:// reference
        if value.starts_with("op://") {
            return Ok(value.to_string());
        }

        if self.vault.is_none() {
            return Err(FnoxError::Provider(format!(
                "Unknown secret vault for: '{}'. Expected value starting with 'op://' or a vault specified in the provider configuration.",
                value
            )));
        }

        // Parse value as "item/field" or just "item"
        // Default field is "password" if not specified
        let parts: Vec<&str> = value.split('/').collect();
        match parts.len() {
            1 => Ok(format!(
                "op://{}/{}/password",
                self.vault.as_ref().unwrap(),
                parts[0]
            )),
            2 => Ok(format!(
                "op://{}/{}/{}",
                self.vault.as_ref().unwrap(),
                parts[0],
                parts[1]
            )),
            _ => Err(FnoxError::Provider(format!(
                "Invalid secret reference format: '{}'. Expected 'item' or 'item/field'",
                value
            ))),
        }
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
            let cow = String::from_utf8_lossy(&output.stderr);
            let replaced = ERROR_PREFIX_RE.replace_all(&cow, "");

            return Err(FnoxError::Provider(format!(
                "1Password CLI command failed: {}",
                replaced.trim(),
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?;

        Ok(stdout.trim().to_string())
    }

    /// Execute op inject command with stdin/stdout
    fn execute_op_inject(&self, input: &str) -> Result<String> {
        tracing::debug!("Executing op inject");

        let mut cmd = Command::new("op");
        if let Some(token) = &*OP_SERVICE_ACCOUNT_TOKEN {
            tracing::debug!(
                "Setting OP_SERVICE_ACCOUNT_TOKEN from LazyLock (token length: {})",
                token.len()
            );
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
        }

        // Add account flag if specified
        if let Some(account) = &self.account {
            cmd.arg("--account").arg(account);
        }

        cmd.arg("inject")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to spawn 'op inject' command: {}. Make sure the 1Password CLI is installed.",
                e
            ))
        })?;

        // Write input to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).map_err(|e| {
                FnoxError::Provider(format!("Failed to write to 'op inject' stdin: {}", e))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            FnoxError::Provider(format!("Failed to wait for 'op inject' command: {}", e))
        })?;

        if !output.status.success() {
            let cow = String::from_utf8_lossy(&output.stderr);
            let replaced = ERROR_PREFIX_RE.replace_all(&cow, "");

            return Err(FnoxError::Provider(format!(
                "1Password CLI 'op inject' command failed: {}",
                replaced.trim(),
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?;

        Ok(stdout)
    }
}

#[async_trait]
impl crate::providers::Provider for OnePasswordProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from 1Password", value);

        let reference = self.value_to_reference(value)?;
        tracing::debug!("Reading 1Password secret: {}", reference);

        // Use 'op read' to fetch the secret
        self.execute_op_command(&["read", &reference])
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        tracing::debug!(
            "Getting {} secrets from 1Password using batch mode",
            secrets.len()
        );

        // If only one secret, fall back to single get_secret
        if secrets.len() == 1 {
            let (key, value) = &secrets[0];
            let result = self.get_secret(value).await;
            let mut map = HashMap::new();
            map.insert(key.clone(), result);
            return map;
        }

        // Build input for op inject
        // Format: KEY1=op://vault/item/field\nKEY2=op://vault/item2/field2\n...
        let mut input = String::new();
        let mut key_order = Vec::new();
        let mut results = HashMap::new();

        for (key, value) in secrets {
            match self.value_to_reference(value) {
                Ok(reference) => {
                    input.push_str(&format!("{}={}\n", key, reference));
                    key_order.push(key.clone());
                }
                Err(e) => {
                    // If we can't build a reference, add error to results
                    tracing::warn!("Failed to build reference for '{}': {}", key, e);
                    results.insert(key.clone(), Err(e));
                }
            }
        }

        // If all secrets failed to build references, return early
        if key_order.is_empty() {
            return results;
        }

        tracing::debug!("Injecting secrets with input:\n{}", input);

        // Execute op inject with stdin
        match self.execute_op_inject(&input) {
            Ok(output) => {
                // Parse output handling multi-line secrets
                // Format: KEY1=value1\nKEY2=value2_line1\nvalue2_line2\nKEY3=value3
                // We need to identify where each key starts and collect all lines until the next key
                let mut current_key: Option<String> = None;
                let mut current_value = String::new();

                for line in output.lines() {
                    // Check if this line starts a new key (contains '=' and the prefix matches a key we're looking for)
                    if let Some(eq_pos) = line.find('=') {
                        let potential_key = &line[..eq_pos];

                        // Check if this is one of our expected keys
                        if key_order.iter().any(|k| k == potential_key) {
                            // Save the previous key-value pair if we have one
                            if let Some(key) = current_key.take() {
                                results.insert(key, Ok(current_value.clone()));
                            }

                            // Start collecting the new key
                            current_key = Some(potential_key.to_string());
                            current_value = line[eq_pos + 1..].to_string();
                            continue;
                        }
                    }

                    // This line is a continuation of the current value
                    if current_key.is_some() {
                        if !current_value.is_empty() {
                            current_value.push('\n');
                        }
                        current_value.push_str(line);
                    }
                }

                // Don't forget the last key-value pair
                if let Some(key) = current_key {
                    results.insert(key, Ok(current_value));
                }

                // Check if any secrets are missing from output
                for key in key_order {
                    if !results.contains_key(&key) {
                        results.insert(
                            key.clone(),
                            Err(FnoxError::Provider(format!(
                                "Secret '{}' not found in op inject output",
                                key
                            ))),
                        );
                    }
                }
            }
            Err(e) => {
                // If op inject failed, fall back to individual get_secret calls
                tracing::warn!("op inject failed, falling back to individual calls: {}", e);
                for (key, value) in secrets {
                    if !results.contains_key(key) {
                        let result = self.get_secret(value).await;
                        results.insert(key.clone(), result);
                    }
                }
            }
        }

        results
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to 1Password");

        // Try to get the current user as a basic connectivity test
        let output = self.execute_op_command(&["whoami"])?;

        tracing::debug!("1Password whoami output: {}", output);

        Ok(())
    }
}

static OP_SERVICE_ACCOUNT_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_OP_SERVICE_ACCOUNT_TOKEN")
        .or_else(|_| env::var("OP_SERVICE_ACCOUNT_TOKEN"))
        .ok()
});
