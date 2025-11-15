use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::process::Command;
use std::{path::Path, sync::LazyLock};

pub struct BitwardenProvider {
    collection: Option<String>,
    organization_id: Option<String>,
    profile: Option<String>,
}

impl BitwardenProvider {
    pub fn new(
        collection: Option<String>,
        organization_id: Option<String>,
        profile: Option<String>,
    ) -> Self {
        Self {
            collection,
            organization_id,
            profile,
        }
    }

    /// Execute bw CLI command with proper authentication
    fn execute_bw_command(&self, args: &[&str]) -> Result<String> {
        tracing::debug!("Executing bw command with args: {:?}", args);

        let mut cmd = Command::new("bw");
        if let Some(profile) = &self.profile {
            match std::env::var("BITWARDENCLI_APPDATA_DIR") {
                Ok(existing_value) => {
                    tracing::warn!(
                        "BITWARDENCLI_APPDATA_DIR is already set to '{}', not overriding with profile '{}'",
                        existing_value,
                        profile
                    );
                }
                Err(_) => {
                    cmd.env(
                        "BITWARDENCLI_APPDATA_DIR",
                        format!(
                            "{}/Bitwarden CLI {}",
                            dirs::config_dir().unwrap().display(),
                            profile
                        ),
                    );
                }
            }
        }

        // Check if session token is available
        let token = if let Some(token) = &*BW_SESSION_TOKEN {
            tracing::debug!(
                "Found BW_SESSION token in environment (length: {})",
                token.len()
            );
            token
        } else {
            // BW_SESSION not found - this will cause bw to fail
            tracing::error!(
                "BW_SESSION token not found in environment. Set BW_SESSION=$(bw unlock --raw) or FNOX_BW_SESSION_TOKEN"
            );
            return Err(FnoxError::Provider(
                "Bitwarden session not found. Please set BW_SESSION environment variable:\n  \
                 export BW_SESSION=$(bw unlock --raw)\n\
                 Or set FNOX_BW_SESSION_TOKEN in your configuration."
                    .to_string(),
            ));
        };

        cmd.args(args);

        // Pass session token as --session flag
        // This is more reliable than environment variable in some contexts
        cmd.arg("--session");
        cmd.arg(token);

        // Close stdin to prevent bw from prompting for passwords interactively
        // This is especially important in CI environments where there's no TTY
        cmd.stdin(std::process::Stdio::null());

        // The BW_SESSION environment variable should be set externally
        // Users should run: export BW_SESSION=$(bw unlock --raw)
        // Or they can set FNOX_BW_SESSION_TOKEN and we'll use that

        let output = cmd.output().map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to execute 'bw' command: {}. Make sure the Bitwarden CLI is installed.",
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::Provider(format!(
                "Bitwarden CLI command failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for BitwardenProvider {
    async fn get_secret(&self, value: &str, _key_file: Option<&Path>) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Bitwarden", value);

        // Parse value as "item/field" or just "item"
        // Default field is "password" if not specified
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

        tracing::debug!(
            "Reading Bitwarden item '{}' field '{}'",
            item_name,
            field_name
        );

        // Build the bw get command
        // bw get <type> <name> [--output json]
        // where type can be: item, username, password, uri, totp, notes, exposed, attachment

        let mut args = vec!["get"];

        // Map field names to bw CLI types
        match field_name {
            "password" => args.push("password"),
            "username" => args.push("username"),
            "notes" => args.push("notes"),
            "uri" | "url" => args.push("uri"),
            "totp" => args.push("totp"),
            // For custom fields, we need to get the item as JSON and parse it
            _ => {
                args.push("item");
                args.push(item_name);
                args.push("--output");
                args.push("json");

                let json_output = self.execute_bw_command(&args)?;

                // Parse JSON and extract custom field
                // This is stubbed - in a real implementation, we'd parse the JSON
                return Err(FnoxError::Provider(format!(
                    "Custom field extraction not yet implemented. Got item JSON: {}",
                    json_output.chars().take(100).collect::<String>()
                )));
            }
        };

        args.push(item_name);

        // Add collection filter if specified
        if let Some(collection) = &self.collection {
            args.push("--collectionid");
            args.push(collection);
        }

        // Add organization filter if specified
        if let Some(org) = &self.organization_id {
            args.push("--organizationid");
            args.push(org);
        }

        self.execute_bw_command(&args)
    }
}

static BW_SESSION_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_BW_SESSION_TOKEN")
        .or_else(|_| env::var("BW_SESSION"))
        .ok()
});
