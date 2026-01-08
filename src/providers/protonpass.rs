extern crate async_trait;
extern crate serde_json;

use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

/// Response from pass-cli item view --output json for custom items
#[derive(Debug, Deserialize)]
struct CustomItemViewResponse {
    item: CustomItemContent,
}

#[derive(Debug, Deserialize)]
struct CustomItemContent {
    id: String,
    share_id: String,
    #[allow(dead_code)]
    vault_id: String,
    content: CustomItemInnerContent,
}

#[derive(Debug, Deserialize)]
struct CustomItemInnerContent {
    #[allow(dead_code)]
    title: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: String,
    #[serde(default)]
    #[allow(dead_code)]
    sections: Vec<Section>,
    #[serde(default)]
    extra_fields: Vec<ExtraField>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Section {
    #[serde(rename = "section_name")]
    #[allow(dead_code)]
    section_name: String,
    #[serde(default)]
    #[allow(dead_code)]
    section_fields: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExtraField {
    name: String,
    content: FieldContent,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
struct FieldContent {
    #[serde(default)]
    #[allow(dead_code)]
    Text: String,
    #[serde(default)]
    #[allow(dead_code)]
    Hidden: String,
}

/// Response from pass-cli item list --output json
#[derive(Debug, Deserialize)]
struct ItemListResponse {
    #[serde(default)]
    items: Vec<ItemListItem>,
}

#[derive(Debug, Deserialize)]
struct ItemListItem {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    share_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    vault_id: String,
    content: ItemContentList,
}

#[derive(Debug, Deserialize)]
struct ItemContentList {
    title: String,
    #[serde(default)]
    #[allow(dead_code)]
    item_uuid: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: String,
}

pub struct ProtonPassProvider {
    item_name: String,
    vault_name: Option<String>,
    share_id: Option<String>,
}

impl ProtonPassProvider {
    pub fn new(item_name: String, vault_name: Option<String>, share_id: Option<String>) -> Self {
        Self {
            item_name,
            vault_name,
            share_id,
        }
    }

    /// Create a custom item template JSON structure
    fn create_custom_item_template(item_name: &str) -> Result<String> {
        let template = serde_json::json!({
            "title": item_name,
            "note": "",
            "sections": [
                {
                    "section_name": "Secrets",
                    "fields": []
                }
            ]
        });

        serde_json::to_string_pretty(&template).map_err(|e| {
            FnoxError::Provider(format!("Failed to create custom item template: {}", e))
        })
    }

    /// Get item ID by searching for item by title
    fn get_item_id_by_title(&self, title: &str) -> Result<String> {
        tracing::debug!("Searching for item with title '{}'", title);

        let mut args = vec![
            "item".to_string(),
            "list".to_string(),
            "--output".to_string(),
            "json".to_string(),
        ];

        if let Some(ref share) = self.share_id {
            args.push("--share-id".to_string());
            args.push(share.clone());
        }

        // Vault name is a positional argument (not a flag)
        if let Some(ref vault) = self.vault_name {
            args.push(vault.clone());
        }

        let output = self.execute_pass_cli_command(&args)?;
        let response: ItemListResponse = serde_json::from_str(&output).map_err(|e| {
            FnoxError::Provider(format!("Failed to parse item list response: {}", e))
        })?;

        for item in response.items {
            if item.content.title == title {
                tracing::debug!("Found item '{}' with ID '{}'", title, item.id);
                return Ok(item.id);
            }
        }

        Err(FnoxError::Provider(format!(
            "Custom item '{}' not found in Proton Pass",
            title
        )))
    }

    /// Check if the custom item exists
    fn custom_item_exists(&self) -> bool {
        self.get_item_id_by_title(&self.item_name).is_ok()
    }

    /// Update a custom field in the item
    /// Since pass-cli creates new fields instead of updating, we recreate the item.
    fn update_custom_field(&self, item_id: &str, field_name: &str, value: &str) -> Result<()> {
        tracing::debug!("Updating field '{}' in item '{}'", field_name, item_id);

        // Get current item data
        let mut args = vec![
            "item".to_string(),
            "view".to_string(),
            "--output".to_string(),
            "json".to_string(),
            "--item-id".to_string(),
            item_id.to_string(),
        ];

        if let Some(ref share) = self.share_id {
            args.push("--share-id".to_string());
            args.push(share.clone());
        } else if let Some(ref vault) = self.vault_name {
            args.push("--vault-name".to_string());
            args.push(vault.clone());
        }

        let output = self.execute_pass_cli_command(&args)?;
        let response: CustomItemViewResponse = serde_json::from_str(&output)
            .map_err(|e| FnoxError::Provider(format!("Failed to parse item response: {}", e)))?;

        let old_item_id = response.item.id.clone();
        let share_id = response.item.share_id.clone();

        // Remove all fields with matching name, add new one
        let target_name = format!("Secret.{}", field_name);
        let extra_fields: Vec<(String, String)> = response
            .item
            .content
            .extra_fields
            .into_iter()
            .filter(|f| f.name != target_name)
            .filter_map(|f| {
                let name = f.name.clone();
                let value = if !f.content.Hidden.is_empty() {
                    f.content.Hidden.clone()
                } else if !f.content.Text.is_empty() {
                    f.content.Text.clone()
                } else {
                    return None;
                };
                Some((name, value))
            })
            .collect();

        // Add new field
        let mut all_fields = extra_fields.clone();
        all_fields.push((target_name.clone(), value.to_string()));

        // Delete old item
        let delete_args = vec![
            "item".to_string(),
            "delete".to_string(),
            "--item-id".to_string(),
            old_item_id.clone(),
            "--share-id".to_string(),
            share_id.clone(),
        ];
        self.execute_pass_cli_command(&delete_args)?;

        // Create new item
        let template = serde_json::json!({
            "title": response.item.content.title,
            "note": response.item.content.note,
            "sections": response.item.content.sections
        });

        let template_json = serde_json::to_string_pretty(&template)
            .map_err(|e| FnoxError::Provider(format!("Failed to create template: {}", e)))?;

        let mut temp_file = NamedTempFile::new()
            .map_err(|e| FnoxError::Provider(format!("Failed to create temp file: {}", e)))?;

        temp_file
            .write_all(template_json.as_bytes())
            .map_err(|e| FnoxError::Provider(format!("Failed to write template: {}", e)))?;
        temp_file.flush()?;

        let temp_path = temp_file
            .path()
            .to_str()
            .ok_or_else(|| FnoxError::Provider("Invalid temp file path".to_string()))?;

        let mut create_cmd = Command::new("pass-cli");
        create_cmd.arg("item").arg("create").arg("custom");
        create_cmd.arg("--from-template").arg(temp_path);

        if let Some(ref vault) = self.vault_name {
            create_cmd.arg("--vault-name").arg(vault);
        }

        create_cmd.stdin(Stdio::null());
        create_cmd.stdout(Stdio::piped());
        create_cmd.stderr(Stdio::piped());

        let output = create_cmd
            .output()
            .map_err(|e| FnoxError::Provider(format!("Failed to create item: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::Provider(format!("Create failed: {}", stderr)));
        }

        // Add all fields using --field
        let new_item_id = self.get_item_id_by_title(&self.item_name)?;

        for (name, val) in all_fields {
            let mut field_args = vec![
                "item".to_string(),
                "update".to_string(),
                "--item-id".to_string(),
                new_item_id.clone(),
                "--field".to_string(),
                format!("{}={}", name, val),
            ];

            if let Some(ref share) = self.share_id {
                field_args.push("--share-id".to_string());
                field_args.push(share.clone());
            } else if let Some(ref vault) = self.vault_name {
                field_args.push("--vault-name".to_string());
                field_args.push(vault.clone());
            }

            self.execute_pass_cli_command(&field_args)?;
        }

        tracing::debug!("Successfully updated field '{}'", field_name);

        Ok(())
    }

    /// Extract a custom field value from the item
    fn extract_custom_field(&self, item_id: &str, field_name: &str) -> Result<String> {
        tracing::debug!("Extracting field '{}' from item '{}'", field_name, item_id);

        let mut args = vec![
            "item".to_string(),
            "view".to_string(),
            "--output".to_string(),
            "json".to_string(),
            "--item-id".to_string(),
            item_id.to_string(),
        ];

        if let Some(ref share) = self.share_id {
            args.push("--share-id".to_string());
            args.push(share.clone());
        } else if let Some(ref vault) = self.vault_name {
            args.push("--vault-name".to_string());
            args.push(vault.clone());
        }

        let output = self.execute_pass_cli_command(&args)?;
        let response: CustomItemViewResponse = serde_json::from_str(&output).map_err(|e| {
            FnoxError::Provider(format!("Failed to parse custom item response: {}", e))
        })?;

        let target_field_name = format!("Secret.{}", field_name);
        let mut found_value = None;
        let mut last_index = None;

        // Find the last occurrence of the field
        for (index, extra_field) in response.item.content.extra_fields.iter().enumerate() {
            if extra_field.name == target_field_name {
                last_index = Some(index);
            }
        }

        // Get the value from the last occurrence
        if let Some(index) = last_index {
            let extra_field = &response.item.content.extra_fields[index];
            tracing::debug!("Found field '{}' at index {}", field_name, index);

            if !extra_field.content.Hidden.is_empty() {
                found_value = Some(extra_field.content.Hidden.clone());
            } else if !extra_field.content.Text.is_empty() {
                found_value = Some(extra_field.content.Text.clone());
            }
        }

        match found_value {
            Some(value) => Ok(value),
            None => Err(FnoxError::Provider(format!(
                "Field '{}' not found in item '{}'",
                field_name, self.item_name
            ))),
        }
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
        tracing::debug!(
            "Getting field '{}' from Proton Pass item '{}'",
            value,
            self.item_name
        );

        let item_id = self.get_item_id_by_title(&self.item_name)?;
        self.extract_custom_field(&item_id, value)
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> std::collections::HashMap<String, Result<String>> {
        tracing::debug!("Getting {} secrets from Proton Pass", secrets.len());

        use std::collections::HashMap;

        let mut results = HashMap::new();

        for (key, value) in secrets {
            let result = self.get_secret(value).await;
            results.insert(key.clone(), result);
        }

        results
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        tracing::debug!(
            "Storing field '{}' in Proton Pass item '{}'",
            key,
            self.item_name
        );

        if self.custom_item_exists() {
            tracing::debug!("Updating existing item '{}'", self.item_name);
            let item_id = self.get_item_id_by_title(&self.item_name)?;
            self.update_custom_field(&item_id, key, value)?;
        } else {
            tracing::debug!("Creating new custom item '{}'", self.item_name);

            let template = Self::create_custom_item_template(&self.item_name)?;

            let mut temp_file = NamedTempFile::new()
                .map_err(|e| FnoxError::Provider(format!("Failed to create temp file: {}", e)))?;

            temp_file.write_all(template.as_bytes()).map_err(|e| {
                FnoxError::Provider(format!("Failed to write template to temp file: {}", e))
            })?;
            temp_file
                .flush()
                .map_err(|e| FnoxError::Provider(format!("Failed to flush temp file: {}", e)))?;

            let temp_path = temp_file
                .path()
                .to_str()
                .ok_or_else(|| FnoxError::Provider("Invalid temp file path".to_string()))?;

            let mut cmd = Command::new("pass-cli");
            cmd.arg("item");
            cmd.arg("create");
            cmd.arg("custom");
            cmd.arg("--from-template");
            cmd.arg(temp_path);

            if let Some(ref vault) = self.vault_name {
                cmd.arg("--vault-name");
                cmd.arg(vault);
            }
            if let Some(ref share) = self.share_id {
                cmd.arg("--share-id");
                cmd.arg(share);
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

            tracing::debug!("Successfully created item '{}'", self.item_name);

            let item_id = self.get_item_id_by_title(&self.item_name)?;
            self.update_custom_field(&item_id, key, value)?;
        }

        Ok(key.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Proton Pass");

        self.execute_pass_cli_command(&["test".to_string()])?;

        tracing::debug!("Proton Pass connection test successful");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_item_template_parsing() {
        let template = ProtonPassProvider::create_custom_item_template("my-project").unwrap();
        let json: serde_json::Value = serde_json::from_str(&template).unwrap();

        assert_eq!(json["title"], "my-project");
        assert_eq!(json["sections"].as_array().unwrap().len(), 1);
        assert_eq!(json["sections"][0]["section_name"], "Secrets");
        assert_eq!(json["sections"][0]["fields"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_provider_initialization() {
        let provider = ProtonPassProvider::new(
            "my-project".to_string(),
            Some("Personal".to_string()),
            Some("share123".to_string()),
        );
        assert_eq!(provider.item_name, "my-project");
        assert_eq!(provider.vault_name, Some("Personal".to_string()));
        assert_eq!(provider.share_id, Some("share123".to_string()));
    }

    #[test]
    fn test_custom_item_exists_logic() {
        let provider = ProtonPassProvider::new("nonexistent-project".to_string(), None, None);

        let result = provider.custom_item_exists();
        assert!(
            !result,
            "custom_item_exists should return false for nonexistent item"
        );
    }
}
