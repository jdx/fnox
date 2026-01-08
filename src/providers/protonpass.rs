extern crate async_trait;
extern crate serde_json;

use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::io::Write;
use std::process::{Command, Stdio};

/// Response from pass-cli item view --output json
#[derive(Debug, Deserialize)]
struct ItemViewResponse {
    data: ItemData,
}

#[derive(Debug, Deserialize)]
struct ItemData {
    item: Item,
}

#[derive(Debug, Deserialize)]
struct Item {
    data: ItemFields,
}

#[derive(Debug, Deserialize)]
struct ItemFields {
    #[serde(rename = "fields")]
    items: Vec<ItemField>,
}

#[derive(Debug, Deserialize)]
struct ItemField {
    name: Option<String>,
    #[serde(rename = "type")]
    field_type: Option<String>,
    value: Option<serde_json::Value>,
}

pub struct ProtonPassProvider {
    vault_name: Option<String>,
    share_id: Option<String>,
}

impl ProtonPassProvider {
    pub fn new(vault_name: Option<String>, share_id: Option<String>) -> Self {
        Self {
            vault_name,
            share_id,
        }
    }

    /// Build pass-cli item view command arguments
    fn build_item_view_command(&self, value: &str) -> Result<Vec<String>> {
        // Check if value is already a full pass:// URI reference
        if value.starts_with("pass://") {
            return Ok(vec![
                "item".to_string(),
                "view".to_string(),
                value.to_string(),
                "--output".to_string(),
                "json".to_string(),
            ]);
        }

        // Parse value as "item/field" or just "item"
        // Default field is "password" if not specified
        let parts: Vec<&str> = value.split('/').collect();

        let (item_name, field_name) = match parts.len() {
            1 => (parts[0], "password"),
            2 => (parts[0], parts[1]),
            _ => {
                return Err(FnoxError::Provider(format!(
                    "Invalid secret reference format: '{}'. Expected 'item' or 'item/field' or 'pass://share_id/item_id/field'",
                    value
                )));
            }
        };

        let mut args = vec![
            "item".to_string(),
            "view".to_string(),
            "--output".to_string(),
            "json".to_string(),
        ];

        // Add vault name if configured
        if let Some(ref vault) = self.vault_name {
            args.push("--vault-name".to_string());
            args.push(vault.clone());
        }

        // Add share ID if configured (and not using full URI)
        if let Some(ref share) = self.share_id {
            args.push("--share-id".to_string());
            args.push(share.clone());
        }

        // Add item title and field
        args.push("--item-title".to_string());
        args.push(item_name.to_string());
        args.push("--field".to_string());
        args.push(field_name.to_string());

        Ok(args)
    }

    /// Execute pass-cli command with proper error handling
    fn execute_pass_cli_command(&self, args: &[String]) -> Result<String> {
        tracing::debug!("Executing pass-cli command with args: {:?}", args);

        let mut cmd = Command::new("pass-cli");
        for arg in args {
            cmd.arg(arg);
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd.output().map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to execute 'pass-cli' command: {}. Make sure Proton Pass CLI is installed.",
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let error_msg = stderr.trim();

            // Check for authentication errors
            if error_msg.contains("authenticated client")
                || error_msg.contains("not logged in")
                || error_msg.contains("There is no session")
                || error_msg.contains("This operation requires an authenticated client")
            {
                return Err(FnoxError::Provider(
                    "Not logged in to Proton Pass. Please run: pass-cli login".to_string(),
                ));
            }

            return Err(FnoxError::Provider(format!(
                "Proton Pass CLI command failed: {}",
                error_msg
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?;

        Ok(stdout.trim().to_string())
    }

    /// Execute pass-cli run command for batch secret injection
    fn execute_pass_cli_run(&self, input: &str) -> Result<String> {
        tracing::debug!("Executing pass-cli run for batch operations");

        let mut cmd = Command::new("pass-cli");
        cmd.arg("run");
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            FnoxError::Provider(format!("Failed to spawn 'pass-cli run' command: {}", e))
        })?;

        // Write input to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).map_err(|e| {
                FnoxError::Provider(format!("Failed to write to 'pass-cli run' stdin: {}", e))
            })?;
            drop(stdin); // Explicitly close stdin to signal EOF
        }

        let output = child.wait_with_output().map_err(|e| {
            FnoxError::Provider(format!("Failed to wait for 'pass-cli run' command: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Check for authentication errors
            if stderr.contains("authenticated client")
                || stderr.contains("not logged in")
                || stderr.contains("There is no session")
                || stderr.contains("This operation requires an authenticated client")
            {
                return Err(FnoxError::Provider(
                    "Not logged in to Proton Pass. Please run: pass-cli login".to_string(),
                ));
            }

            return Err(FnoxError::Provider(format!(
                "Proton Pass CLI 'run' command failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?;

        Ok(stdout)
    }
}

#[async_trait]
impl crate::providers::Provider for ProtonPassProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteRead]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Proton Pass", value);

        let args = self.build_item_view_command(value)?;
        tracing::debug!("Proton Pass command args: {:?}", args);

        // Use 'pass-cli item view' with JSON output
        let output = self.execute_pass_cli_command(&args)?;

        // Parse JSON output to extract field value
        let response: ItemViewResponse = serde_json::from_str(&output).map_err(|e| {
            FnoxError::Provider(format!("Failed to parse Proton Pass JSON response: {}", e))
        })?;

        // Extract field value from item data
        let fields = &response.data.item.data.items;

        // Find the field we want
        // The command should have already filtered to a specific field via --field flag
        // But we should still find the right field in case of multiple fields
        let field = fields
            .iter()
            .find(|f| f.value.is_some())
            .ok_or_else(|| FnoxError::Provider("No value found in Proton Pass item".to_string()))?;

        match &field.value {
            Some(serde_json::Value::String(s)) => Ok(s.clone()),
            Some(serde_json::Value::Number(n)) => Ok(n.to_string()),
            Some(serde_json::Value::Bool(b)) => Ok(b.to_string()),
            Some(v) => Err(FnoxError::Provider(format!(
                "Unexpected field value type in Proton Pass item: {:?}",
                v
            ))),
            None => Err(FnoxError::Provider(
                "Field value is null in Proton Pass item".to_string(),
            )),
        }
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> std::collections::HashMap<String, Result<String>> {
        tracing::debug!(
            "Getting {} secrets from Proton Pass using batch mode",
            secrets.len()
        );

        use std::collections::HashMap;

        // If only one secret, fall back to single get_secret
        if secrets.len() == 1 {
            let (key, value) = &secrets[0];
            let result = self.get_secret(value).await;
            let mut map = HashMap::new();
            map.insert(key.clone(), result);
            return map;
        }

        // Build input for pass-cli run
        // Format: KEY1=pass://share_id/item_id/field\nKEY2=pass://share_id/item2_id/field2\n...
        let mut input = String::new();
        let mut key_order = Vec::new();
        let mut results = HashMap::new();

        for (key, value) in secrets {
            match self.build_item_view_command(value) {
                Ok(args) => {
                    // Convert args to URI format for pass-cli run
                    // pass-cli run expects: KEY=pass://URI format
                    if args.len() >= 3 && args[1] == "view" {
                        // Extract URI from args if it's a full URI
                        if args[2].starts_with("pass://") {
                            let uri = args[2].clone();
                            input.push_str(&format!("{}={}\n", key, uri));
                            key_order.push(key.clone());
                        } else {
                            // Construct URI from flags - this is complex, so fall back to individual calls
                            tracing::warn!(
                                "Cannot convert flags-based reference to URI for '{}', will fetch individually",
                                key
                            );
                            continue;
                        }
                    } else {
                        tracing::warn!(
                            "Invalid args format for '{}', will fetch individually",
                            key
                        );
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to build reference for '{}': {}", key, e);
                    results.insert(key.clone(), Err(e));
                }
            }
        }

        // If all secrets failed to build references, return early
        if key_order.is_empty() {
            // Fall back to individual calls for all secrets
            tracing::warn!("No URIs could be built, falling back to individual calls");
            for (key, value) in secrets {
                if !results.contains_key(key) {
                    let result = self.get_secret(value).await;
                    results.insert(key.clone(), result);
                }
            }
            return results;
        }

        tracing::debug!("Injecting secrets with input:\n{}", input);

        // Execute pass-cli run with stdin
        match self.execute_pass_cli_run(&input) {
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
                                "Secret '{}' not found in pass-cli run output",
                                key
                            ))),
                        );
                    }
                }
            }
            Err(e) => {
                // If pass-cli run failed, fall back to individual get_secret calls
                tracing::warn!(
                    "pass-cli run failed, falling back to individual calls: {}",
                    e
                );
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
        tracing::debug!("Testing connection to Proton Pass");

        // Try to test authentication status
        self.execute_pass_cli_command(&["test".to_string()])?;

        tracing::debug!("Proton Pass connection test successful");
        Ok(())
    }
}
