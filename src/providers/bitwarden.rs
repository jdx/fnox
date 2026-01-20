use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::process::Command;
use std::sync::LazyLock;

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

impl fmt::Display for BitwardenBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitwardenBackend::Bw => write!(f, "bw"),
            BitwardenBackend::Rbw => write!(f, "rbw"),
        }
    }
}

impl BitwardenProvider {
    pub fn new(
        collection: Option<String>,
        organization_id: Option<String>,
        profile: Option<String>,
        backend: Option<BitwardenBackend>,
    ) -> Self {
        Self {
            collection,
            organization_id,
            profile,
            backend: backend.unwrap_or(BitwardenBackend::Bw),
        }
    }

    fn build_command(&self, kind: Option<&str>, item_name: &str) -> Result<Command> {
        match &self.backend {
            BitwardenBackend::Bw => self.build_bw_command(kind, item_name),
            BitwardenBackend::Rbw => self.build_rbw_command(kind, item_name),
        }
    }

    fn build_bw_command(&self, kind: Option<&str>, item_name: &str) -> Result<Command> {
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
                cmd.args(["--output", "json"]);
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
            return Err(FnoxError::ProviderAuthFailed {
                provider: "Bitwarden".to_string(),
                details: "Session token not found".to_string(),
                hint: "Set BW_SESSION=$(bw unlock --raw) or FNOX_BW_SESSION_TOKEN".to_string(),
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

    fn build_rbw_command(&self, kind: Option<&str>, item_name: &str) -> Result<Command> {
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
            Some(_) => {
                // custom field path: fetch full JSON; later code can still error out
                cmd.args(["get", item_name, "--raw"]);
            }
        }

        if let Some(profile) = &self.profile {
            cmd.env("RBW_PROFILE", profile);
        }

        Ok(cmd)
    }

    fn execute_command(&self, cmd: &mut Command) -> Result<String> {
        // Close stdin to prevent bw from prompting for passwords interactively
        // This is especially important in CI environments where there's no TTY
        cmd.stdin(std::process::Stdio::null());

        // The BW_SESSION environment variable should be set externally
        // Users should run: export BW_SESSION=$(bw unlock --raw)
        // Or they can set FNOX_BW_SESSION_TOKEN and we'll use that

        let cli = match self.backend {
            BitwardenBackend::Bw => "bw",
            BitwardenBackend::Rbw => "rbw",
        };
        let output = cmd.output().map_err(|e| {
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
                    hint: format!("Run '{} unlock' and set BW_SESSION", cli),
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
}

#[async_trait]
impl crate::providers::Provider for BitwardenProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Bitwarden", value);

        // Parse value as "item/field" or just "item"
        // Default field is "password" if not specified
        let parts: Vec<&str> = value.split('/').collect();

        let (item_name, field_name) = match parts.len() {
            1 => (parts[0], "password"),
            2 => (parts[0], parts[1]),
            _ => {
                return Err(FnoxError::ProviderInvalidResponse {
                    provider: "Bitwarden".to_string(),
                    details: format!("Invalid secret reference format: '{}'", value),
                    hint: "Expected 'item' or 'item/field'".to_string(),
                    url: "https://fnox.jdx.dev/providers/bitwarden".to_string(),
                });
            }
        };

        tracing::debug!(
            "Reading Bitwarden item '{}' field '{}'",
            item_name,
            field_name
        );

        let mut cmd = self.build_command(Some(field_name), item_name)?;
        self.execute_command(&mut cmd)
    }
}

static BW_SESSION_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_BW_SESSION")
        .or_else(|_| env::var("BW_SESSION"))
        .ok()
});
