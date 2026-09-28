use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use tokio::process::Command;

pub struct BitwardenProvider {
    collection: Option<String>,
    organization_id: Option<String>,
    profile: Option<String>,
    backend: BitwardenBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BitwardenBackend {
    Bw,
    Rbw,
}

#[derive(Debug, Deserialize)]
struct BitwardenItem {
    #[serde(default)]
    fields: Vec<BitwardenField>,
}

#[derive(Debug, Deserialize)]
struct BitwardenField {
    name: Option<String>,
    value: Option<String>,
}

impl fmt::Display for BitwardenBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitwardenBackend::Bw => write!(f, "bw"),
            BitwardenBackend::Rbw => write!(f, "rbw"),
        }
    }
}

impl BitwardenProvider {
    fn parse_reference(value: &str) -> (&str, &str) {
        value.split_once('/').unwrap_or((value, "password"))
    }

    pub fn new(
        collection: Option<String>,
        organization_id: Option<String>,
        profile: Option<String>,
        backend: Option<BitwardenBackend>,
    ) -> Result<Self> {
        Ok(Self {
            collection,
            organization_id,
            profile,
            backend: backend.unwrap_or(BitwardenBackend::Bw),
        })
    }

    fn build_command(
        &self,
        kind: Option<&str>,
        item_name: &str,
    ) -> Result<tokio::process::Command> {
        match &self.backend {
            BitwardenBackend::Bw => self.build_bw_command(kind, item_name),
            BitwardenBackend::Rbw => self.build_rbw_command(kind, item_name),
        }
    }

    fn build_bw_command(
        &self,
        kind: Option<&str>,
        item_name: &str,
    ) -> Result<tokio::process::Command> {
        // Build the bw get command
        // bw get <type> <name> [--output json]
        // where type can be: item, username, password, uri, totp, notes, exposed, attachment

        let mut cmd = Command::new("bw");
        cmd.arg("get");

        // Determine the field type to retrieve
        let field_type = match kind {
            None | Some("password") => Some("password"),
            Some("username") => Some("username"),
            Some("notes") => Some("notes"),
            Some("uri") | Some("url") => Some("uri"),
            Some("totp") => Some("totp"),
            Some(_) => {
                // For custom fields, we need the full item JSON
                cmd.arg("item");
                cmd.arg(item_name);
                None // Special case handled, no field type needed
            }
        };

        // For standard field types, add the field type and item name
        if let Some(field_type) = field_type {
            cmd.arg(field_type);
            cmd.arg(item_name);
        }

        if let Some(ref coll) = self.collection {
            cmd.args(["--collectionid", coll]);
        }
        if let Some(ref org) = self.organization_id {
            cmd.args(["--organizationid", org]);
        }

        // Check if session token is available
        let session_token = bw_session_token();
        let token = if let Some(token) = &session_token {
            tracing::debug!(
                "Found BW_SESSION token in environment (length: {})",
                token.len()
            );
            token
        } else {
            // BW_SESSION not found - this will cause bw to fail
            tracing::error!(
                "BW_SESSION token not found in environment. Set BW_SESSION=$(bw unlock --raw) or FNOX_BW_SESSION"
            );
            return Err(FnoxError::ProviderAuthFailed {
                provider: "Bitwarden".to_string(),
                details: "Session token not found".to_string(),
                hint: "Set BW_SESSION=$(bw unlock --raw) or FNOX_BW_SESSION".to_string(),
                url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
            });
        };

        // Pass session token as --session flag
        // This is more reliable than environment variable in some contexts
        cmd.arg("--session");
        cmd.arg(token);

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

        Ok(cmd)
    }

    fn build_rbw_command(
        &self,
        kind: Option<&str>,
        item_name: &str,
    ) -> Result<tokio::process::Command> {
        let mut cmd = Command::new("rbw");

        match kind {
            None | Some("password") => {
                // password is default output
                cmd.args(["get", item_name]);
            }
            Some("username") => {
                cmd.args(["get", item_name, "--field", "username"]);
            }
            Some("notes") => {
                cmd.args(["get", item_name, "--field", "notes"]);
            }
            Some("uri") | Some("url") => {
                cmd.args(["get", item_name, "--field", "uri"]);
            }
            Some("totp") => {
                // rbw uses a separate subcommand for TOTP
                cmd.args(["code", item_name]);
            }
            Some(field) => {
                cmd.args(["get", item_name, "--field", field]);
            }
        }

        if let Some(profile) = &self.profile {
            cmd.env("RBW_PROFILE", profile);
        }

        Ok(cmd)
    }

    async fn execute_command(&self, cmd: &mut Command) -> Result<String> {
        // Close stdin to prevent bw from prompting for passwords interactively
        // This is especially important in CI environments where there's no TTY
        cmd.stdin(std::process::Stdio::null());

        // The BW_SESSION environment variable should be set externally
        // Users should run: export BW_SESSION=$(bw unlock --raw)
        // Or they can set FNOX_BW_SESSION and we'll use that

        let cli = match self.backend {
            BitwardenBackend::Bw => "bw",
            BitwardenBackend::Rbw => "rbw",
        };
        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "Bitwarden".to_string(),
                    cli: cli.to_string(),
                    install_hint: match self.backend {
                        BitwardenBackend::Bw => "brew install bitwarden-cli".to_string(),
                        BitwardenBackend::Rbw => "brew install rbw".to_string(),
                    },
                    url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "Bitwarden".to_string(),
                    details: e.to_string(),
                    hint: format!("Check that {} is installed and accessible", cli),
                    url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_str = stderr.trim();

            // Check for Bitwarden CLI auth errors (tested with bw CLI)
            // More specific patterns to avoid false positives
            if stderr_str.contains("vault is locked")
                || stderr_str.contains("You are not logged in")
                || stderr_str.contains("session key is invalid")
                || stderr_str.contains("BW_SESSION")
                || stderr_str.contains("You must login")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Bitwarden".to_string(),
                    details: stderr_str.to_string(),
                    hint: format!("Run '{cli} unlock' and set BW_SESSION or FNOX_BW_SESSION"),
                    url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
                });
            }

            return Err(FnoxError::ProviderCliFailed {
                provider: "Bitwarden".to_string(),
                details: stderr_str.to_string(),
                hint: "Check your Bitwarden configuration".to_string(),
                url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden".to_string(),
                details: format!("Invalid UTF-8: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }

    fn extract_custom_field(
        &self,
        item_name: &str,
        field_name: &str,
        json: &str,
    ) -> Result<String> {
        let item: BitwardenItem =
            serde_json::from_str(json).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden".to_string(),
                details: format!("Failed to parse item '{}': {}", item_name, e),
                hint: "Check that the Bitwarden CLI returned a valid item".to_string(),
                url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
            })?;

        let field = item
            .fields
            .into_iter()
            .find(|field| field.name.as_deref() == Some(field_name))
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden".to_string(),
                details: format!(
                    "Custom field '{}' not found in item '{}'",
                    field_name, item_name
                ),
                hint: "Check the custom field name and capitalization".to_string(),
                url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
            })?;

        field
            .value
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Bitwarden".to_string(),
                details: format!(
                    "Custom field '{}' in item '{}' has no value",
                    field_name, item_name
                ),
                hint: "Set a value for the custom field in Bitwarden".to_string(),
                url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
            })
    }
}

#[async_trait]
impl crate::providers::Provider for BitwardenProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Bitwarden", value);

        // Parse value as "item/field" or just "item"
        // Default field is "password" if not specified
        let (item_name, field_name) = Self::parse_reference(value);

        tracing::debug!(
            "Reading Bitwarden item '{}' field '{}'",
            item_name,
            field_name
        );

        let is_custom_field = !matches!(
            field_name,
            "password" | "username" | "notes" | "uri" | "url" | "totp"
        );
        let mut cmd = self.build_command(Some(field_name), item_name)?;
        let output = self.execute_command(&mut cmd).await?;

        if is_custom_field && self.backend == BitwardenBackend::Bw {
            self.extract_custom_field(item_name, field_name, &output)
        } else {
            Ok(output)
        }
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &["BW_SESSION", "FNOX_BW_SESSION"]
}

fn bw_session_token() -> Option<String> {
    env::var("FNOX_BW_SESSION")
        .or_else(|_| env::var("BW_SESSION"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(backend: BitwardenBackend) -> BitwardenProvider {
        BitwardenProvider::new(None, None, None, Some(backend)).unwrap()
    }

    #[test]
    fn extracts_custom_field_from_bw_item() {
        let json = r#"{
            "fields": [
                {"name": "API/Key", "value": "secret-value", "type": 1},
                {"name": "Region", "value": "us-east-1", "type": 0}
            ]
        }"#;

        let value = provider(BitwardenBackend::Bw)
            .extract_custom_field("Database", "API/Key", json)
            .unwrap();

        assert_eq!(value, "secret-value");
    }

    #[test]
    fn errors_when_custom_field_is_missing() {
        let error = provider(BitwardenBackend::Bw)
            .extract_custom_field("Database", "Missing", r#"{"fields": []}"#)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Custom field 'Missing' not found")
        );
    }

    #[test]
    fn rbw_uses_field_flag_for_custom_fields() {
        let command = provider(BitwardenBackend::Rbw)
            .build_rbw_command(Some("API/Key"), "Database")
            .unwrap();
        let args: Vec<_> = command.as_std().get_args().collect();

        assert_eq!(args, ["get", "Database", "--field", "API/Key"]);
    }

    #[test]
    fn parses_custom_field_name_with_slashes() {
        assert_eq!(
            BitwardenProvider::parse_reference("Database/API/Key"),
            ("Database", "API/Key")
        );
    }
}
