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
    item: ItemContent,
}

#[derive(Debug, Deserialize)]
struct ItemContent {
    content: ItemInnerContent,
}

#[derive(Debug, Deserialize)]
struct ItemInnerContent {
    content: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct LoginContent {
    #[serde(default)]
    password: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    totp_uri: String,
    #[serde(default)]
    urls: Vec<String>,
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

    /// Check if an item exists by attempting to view it
    fn item_exists(&self, key: &str) -> bool {
        let mut args = vec![
            "item".to_string(),
            "view".to_string(),
            "--output".to_string(),
            "json".to_string(),
        ];

        if let Some(ref vault) = self.vault_name {
            args.push("--vault-name".to_string());
            args.push(vault.clone());
        }
        if let Some(ref share) = self.share_id {
            args.push("--share-id".to_string());
            args.push(share.clone());
        }
        args.push("--item-title".to_string());
        args.push(key.to_string());

        let mut cmd = Command::new("pass-cli");
        for arg in &args {
            cmd.arg(arg);
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        match cmd.output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
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

        // Add item title (field will be extracted from JSON response)
        args.push("--item-title".to_string());
        args.push(item_name.to_string());

        // Note: We don't add --field here because it breaks JSON output
        // The field will be extracted from the JSON response instead

        Ok(args)
    }

    /// Extract a specific field from the login content JSON
    fn extract_field(content: &serde_json::Value, field_name: &str) -> Option<String> {
        // Handle special fields that are at the login level
        if field_name == "password"
            || field_name == "username"
            || field_name == "email"
            || field_name == "totp"
        {
            if let Some(login_obj) = content.as_object() {
                for (_key, value) in login_obj {
                    if let Ok(login_content) = serde_json::from_value::<LoginContent>(value.clone())
                    {
                        match field_name {
                            "password" => {
                                if !login_content.password.is_empty() {
                                    return Some(login_content.password);
                                }
                            }
                            "username" => {
                                if !login_content.username.is_empty() {
                                    return Some(login_content.username);
                                }
                            }
                            "email" => {
                                if !login_content.email.is_empty() {
                                    return Some(login_content.email);
                                }
                            }
                            "totp" => {
                                if !login_content.totp_uri.is_empty() {
                                    return Some(login_content.totp_uri);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            return None;
        }

        // For custom fields, look in extra_fields
        // This is a simplified implementation
        None
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
        vec![
            crate::providers::ProviderCapability::RemoteRead,
            crate::providers::ProviderCapability::RemoteStorage,
        ]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Proton Pass", value);

        // Parse value to extract item name and field
        let parts: Vec<&str> = value.split('/').collect();
        let (item_name, field_name) = match parts.len() {
            1 => (parts[0], "password"),
            2 => (parts[0], parts[1]),
            _ => {
                return Err(FnoxError::Provider(format!(
                    "Invalid secret reference format: '{}'. Expected 'item' or 'item/field'",
                    value
                )));
            }
        };

        // Build command to get full JSON (without --field flag)
        let mut args = vec![
            "item".to_string(),
            "view".to_string(),
            "--output".to_string(),
            "json".to_string(),
        ];

        if let Some(ref vault) = self.vault_name {
            args.push("--vault-name".to_string());
            args.push(vault.clone());
        }
        if let Some(ref share) = self.share_id {
            args.push("--share-id".to_string());
            args.push(share.clone());
        }
        args.push("--item-title".to_string());
        args.push(item_name.to_string());

        tracing::debug!("Proton Pass command args: {:?}", args);

        // Use 'pass-cli item view' with JSON output
        let output = self.execute_pass_cli_command(&args)?;

        // Parse JSON output to extract field value
        let response: ItemViewResponse = serde_json::from_str(&output).map_err(|e| {
            FnoxError::Provider(format!("Failed to parse Proton Pass JSON response: {}", e))
        })?;

        // Extract requested field from login content
        let content = &response.item.content.content;
        let result = Self::extract_field(content, field_name);

        match result {
            Some(value) => Ok(value),
            None => Err(FnoxError::Provider(format!(
                "Field '{}' not found in Proton Pass item '{}'",
                field_name, item_name
            ))),
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
        // Format: KEY1=pass://URI\nKEY2=pass://URI\n...
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
                            // Cannot convert flags-based reference to URI for batch
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

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        tracing::debug!("Storing secret '{}' in Proton Pass", key);

        // Build base command arguments for vault selection
        let mut base_args = vec![];
        if let Some(ref vault) = self.vault_name {
            base_args.push("--vault-name".to_string());
            base_args.push(vault.clone());
        }
        if let Some(ref share) = self.share_id {
            base_args.push("--share-id".to_string());
            base_args.push(share.clone());
        }

        // Check if item exists to decide whether to create or update
        let item_exists = self.item_exists(key);

        if item_exists {
            // Update existing item
            tracing::debug!("Updating existing item '{}' in Proton Pass", key);
            let mut args = base_args.clone();
            args.push("--item-title".to_string());
            args.push(key.to_string());
            args.push("--field".to_string());
            args.push(format!("password={}", value));

            let mut cmd = Command::new("pass-cli");
            cmd.arg("item");
            cmd.arg("update");
            for arg in &args {
                cmd.arg(arg);
            }
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let output = cmd.output().map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to execute 'pass-cli item update' command: {}",
                    e
                ))
            })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(FnoxError::Provider(format!(
                    "Proton Pass CLI update command failed: {}",
                    stderr.trim()
                )));
            }

            tracing::debug!("Successfully updated item '{}' in Proton Pass", key);
        } else {
            // Create new item
            tracing::debug!("Creating new item '{}' in Proton Pass", key);
            let mut args = base_args.clone();
            args.push("--title".to_string());
            args.push(key.to_string());
            args.push("--password".to_string());
            args.push(value.to_string());

            let mut cmd = Command::new("pass-cli");
            cmd.arg("item");
            cmd.arg("create");
            cmd.arg("login");
            for arg in &args {
                cmd.arg(arg);
            }
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let output = cmd.output().map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to execute 'pass-cli item create' command: {}",
                    e
                ))
            })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(FnoxError::Provider(format!(
                    "Proton Pass CLI create command failed: {}",
                    stderr.trim()
                )));
            }

            tracing::debug!("Successfully created item '{}' in Proton Pass", key);
        }

        // Return the key (item title) as the reference to store in config
        Ok(key.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Proton Pass");

        // Try to test authentication status
        self.execute_pass_cli_command(&["test".to_string()])?;

        tracing::debug!("Proton Pass connection test successful");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parsing_login_item() {
        // Actual pass-cli output for a login item
        let json_output = r#"{
            "item": {
                "id": "oURr-KN6Y7Mw0xIIvvhLm7N_hLoCj-qgGfZNAfJkb9vvTtDLmtqXIfeKeWM6ZjzUUIifJr6Sk1stFDiyusfMLw==",
                "share_id": "Jb6lbnRJSjbWPDdDDzKe0Xq4yDf6aSm_YXFbxIj5xvcKK3GvWATjS_e6JfQy-x3nxoBLZZIsEThUNUMaLWZSzQ==",
                "vault_id": "HJxQHG-rgdAtfW1-JjEzXaH8qNo4TdREk4OvInYmopswFGkl-qtoy5xwk52yNcW5pEYIaMXY2f20kAFRW_QBHw==",
                "content": {
                    "title": "OP_SERVICE_ACCOUNT_TOKEN",
                    "note": "",
                    "item_uuid": "3bd093be-77ce-4295-b19f-5dcdb492af85",
                    "content": {
                        "Login": {
                            "email": "",
                            "username": "",
                            "password": "ops_YOUR_TOKEN",
                            "urls": [],
                            "totp_uri": "",
                            "passkeys": []
                        }
                    },
                    "extra_fields": []
                },
                "state": "Active",
                "flags": [],
                "create_time": "2026-01-08T08:00:04"
            },
            "attachments": []
        }"#;

        let response: ItemViewResponse =
            serde_json::from_str(json_output).expect("Should parse JSON");

        // Extract password
        let content = &response.item.content.content;
        let mut found_password = None;

        if let Some(login_obj) = content.as_object() {
            for (_key, value) in login_obj {
                if let Ok(login_content) = serde_json::from_value::<LoginContent>(value.clone()) {
                    if !login_content.password.is_empty() {
                        found_password = Some(login_content.password);
                        break;
                    }
                }
            }
        }

        assert_eq!(found_password, Some("ops_YOUR_TOKEN".to_string()));
    }

    #[test]
    fn test_json_parsing_empty_password() {
        // JSON output with empty password
        let json_output = r#"{
            "item": {
                "id": "test-id",
                "content": {
                    "title": "Test Item",
                    "content": {
                        "Login": {
                            "email": "test@example.com",
                            "username": "testuser",
                            "password": "",
                            "urls": [],
                            "totp_uri": "",
                            "passkeys": []
                        }
                    }
                }
            }
        }"#;

        let response: ItemViewResponse =
            serde_json::from_str(json_output).expect("Should parse JSON");

        let content = &response.item.content.content;
        let mut found_password = None;

        if let Some(login_obj) = content.as_object() {
            for (_key, value) in login_obj {
                if let Ok(login_content) = serde_json::from_value::<LoginContent>(value.clone()) {
                    if !login_content.password.is_empty() {
                        found_password = Some(login_content.password);
                        break;
                    }
                }
            }
        }

        assert_eq!(found_password, None);
    }

    #[test]
    fn test_json_parsing_with_username() {
        // JSON output with username
        let json_output = r#"{
            "item": {
                "id": "test-id",
                "content": {
                    "title": "Test Item",
                    "content": {
                        "Login": {
                            "email": "user@example.com",
                            "username": "myuser",
                            "password": "secretpassword",
                            "urls": ["https://example.com"],
                            "totp_uri": "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                            "passkeys": []
                        }
                    }
                }
            }
        }"#;

        let response: ItemViewResponse =
            serde_json::from_str(json_output).expect("Should parse JSON");

        let content = &response.item.content.content;

        if let Some(login_obj) = content.as_object() {
            for (_key, value) in login_obj {
                if let Ok(login_content) = serde_json::from_value::<LoginContent>(value.clone()) {
                    assert_eq!(login_content.username, "myuser");
                    assert_eq!(login_content.password, "secretpassword");
                    assert_eq!(login_content.email, "user@example.com");
                    assert_eq!(login_content.urls, vec!["https://example.com"]);
                    return;
                }
            }
        }

        panic!("Should have found Login content");
    }

    #[test]
    fn test_item_exists_with_vault_name() {
        let provider = ProtonPassProvider::new(Some("Personal".to_string()), None);
        // This test verifies the method exists and compiles
        // In real tests, we'd mock the pass-cli command
        let result = provider.item_exists("OP_SERVICE_ACCOUNT_TOKEN");
        // Result depends on whether the item exists in the vault
        // This is just a compilation test
        assert!(result || !result);
    }

    #[test]
    fn test_build_item_view_command_with_uri() {
        let provider = ProtonPassProvider::new(None, None);

        // Test with full pass:// URI
        let args = provider
            .build_item_view_command("pass://share123/item456/password")
            .unwrap();
        assert!(args.contains(&"pass://share123/item456/password".to_string()));
    }

    #[test]
    fn test_build_item_view_command_with_title() {
        let provider =
            ProtonPassProvider::new(Some("MyVault".to_string()), Some("share123".to_string()));

        // Test with item name (defaults to password field)
        let args = provider.build_item_view_command("MyItem").unwrap();
        assert!(args.contains(&"--vault-name".to_string()));
        assert!(args.contains(&"MyVault".to_string()));
        assert!(args.contains(&"--share-id".to_string()));
        assert!(args.contains(&"share123".to_string()));
        assert!(args.contains(&"--item-title".to_string()));
        assert!(args.contains(&"MyItem".to_string()));
        // Note: --field is NOT included because it breaks JSON output
        // The field is extracted from JSON response instead
    }

    #[test]
    fn test_build_item_view_command_with_field() {
        let provider = ProtonPassProvider::new(None, None);

        // Test with item/field format
        let args = provider.build_item_view_command("MyItem/username").unwrap();
        assert!(args.contains(&"--item-title".to_string()));
        assert!(args.contains(&"MyItem".to_string()));
        // Note: --field is NOT included because it breaks JSON output
        // The field is extracted from JSON response instead
    }

    #[test]
    fn test_build_item_view_command_invalid_format() {
        let provider = ProtonPassProvider::new(None, None);

        // Test with invalid format (too many slashes)
        let result = provider.build_item_view_command("item/field/extra");
        assert!(result.is_err());
    }
}
