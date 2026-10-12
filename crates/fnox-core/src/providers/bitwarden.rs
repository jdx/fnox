use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use tokio::process::Command;
use tokio::sync::OnceCell;

const URL: &str = "https://fnox.jdx.dev/providers/bitwarden";

/// Reads secrets from a Bitwarden vault through the `bw` or `rbw` CLI.
pub struct BitwardenProvider {
    collection: Option<String>,
    organization_id: Option<String>,
    profile: Option<String>,
    /// Folder name or nested path (e.g. `MyApp/Production`) that scopes item lookups.
    folder: Option<String>,
    backend: BitwardenBackend,
    /// `bw` folder ID for `folder`, resolved on first use and shared by later lookups.
    folder_id: OnceCell<String>,
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

/// One folder or item from `bw list` JSON output. The built-in "No Folder" entry has no `id`.
#[derive(Debug, Deserialize)]
struct BitwardenListEntry {
    id: Option<String>,
    name: String,
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

    /// Creates a provider from its config fields; `backend` defaults to `bw`.
    pub fn new(
        collection: Option<String>,
        organization_id: Option<String>,
        profile: Option<String>,
        folder: Option<String>,
        backend: Option<BitwardenBackend>,
    ) -> Result<Self> {
        Ok(Self {
            collection,
            organization_id,
            profile,
            folder,
            backend: backend.unwrap_or(BitwardenBackend::Bw),
            folder_id: OnceCell::new(),
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

    /// Builds `bw get <field> <item>`, or `bw get item <item>` for custom fields.
    ///
    /// `item_name` may be an item name or, for folder-scoped lookups, a resolved item ID.
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

        self.apply_bw_session_and_profile(&mut cmd)?;

        Ok(cmd)
    }

    /// Builds `bw list <args>` with the session token and profile applied.
    fn build_bw_list_command(&self, args: &[&str]) -> Result<tokio::process::Command> {
        let mut cmd = Command::new("bw");
        cmd.arg("list");
        cmd.args(args);
        self.apply_bw_session_and_profile(&mut cmd)?;
        Ok(cmd)
    }

    /// Adds `--session` from `FNOX_BW_SESSION`/`BW_SESSION` and points `bw` at the configured
    /// profile's data directory, unless `BITWARDENCLI_APPDATA_DIR` is already set.
    ///
    /// Fails with an auth error when no session token is available.
    fn apply_bw_session_and_profile(&self, cmd: &mut Command) -> Result<()> {
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

        Ok(())
    }

    /// Builds `rbw get` (or `rbw code` for TOTP), adding `--folder` when a folder is set.
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

        if let Some(folder) = &self.folder {
            cmd.args(["--folder", folder]);
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

    /// Returns the `bw` folder ID for `folder`, querying `bw list folders` only once per provider.
    async fn resolve_bw_folder_id(&self, folder: &str) -> Result<String> {
        self.folder_id
            .get_or_try_init(|| async {
                let mut cmd = self.build_bw_list_command(&["folders", "--search", folder])?;
                let output = self.execute_command(&mut cmd).await?;
                let folders = parse_list_entries("folders", &output)?;
                select_entry("folder", folder, folders)
            })
            .await
            .cloned()
    }

    /// Finds the ID of `item_name` inside `folder`, honoring collection and organization filters.
    ///
    /// A missing item is reported as `<folder>/<item>` not found.
    async fn resolve_bw_item_id(&self, folder: &str, item_name: &str) -> Result<String> {
        let folder_id = self.resolve_bw_folder_id(folder).await?;
        let mut args = vec!["items", "--folderid", &folder_id, "--search", item_name];
        if let Some(coll) = &self.collection {
            args.extend(["--collectionid", coll]);
        }
        if let Some(org) = &self.organization_id {
            args.extend(["--organizationid", org]);
        }
        let mut cmd = self.build_bw_list_command(&args)?;
        let output = self.execute_command(&mut cmd).await?;
        let items = parse_list_entries("items", &output)?;
        select_entry("item", item_name, items).map_err(|e| match e {
            FnoxError::ProviderSecretNotFound { hint, url, .. } => {
                FnoxError::ProviderSecretNotFound {
                    provider: "Bitwarden".to_string(),
                    secret: format!("{folder}/{item_name}"),
                    hint,
                    url,
                }
            }
            e => e,
        })
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
    /// Resolves an `item` or `item/field` reference; `field` defaults to `password`.
    ///
    /// With `folder` set, `rbw` filters by folder directly, while `bw` first resolves the
    /// item's ID inside that folder and fetches by ID.
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
        let mut cmd = match (&self.backend, &self.folder) {
            (BitwardenBackend::Bw, Some(folder)) => {
                let item_id = self.resolve_bw_item_id(folder, item_name).await?;
                self.build_command(Some(field_name), &item_id)?
            }
            _ => self.build_command(Some(field_name), item_name)?,
        };
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

/// Parses `bw list <kind>` JSON output.
fn parse_list_entries(kind: &str, json: &str) -> Result<Vec<BitwardenListEntry>> {
    serde_json::from_str(json).map_err(|e| FnoxError::ProviderInvalidResponse {
        provider: "Bitwarden".to_string(),
        details: format!("Failed to parse 'bw list {kind}' output: {e}"),
        hint: "Check that the Bitwarden CLI returned valid JSON".to_string(),
        url: URL.to_string(),
    })
}

/// Picks the single entry named `name` from `bw list --search` results and returns its ID.
///
/// Exact name matches win. Otherwise, names containing `name` (case-insensitive) are used,
/// so search hits on other fields such as usernames or URIs are ignored. Errors if nothing
/// matches or if more than one entry does.
fn select_entry(kind: &str, name: &str, entries: Vec<BitwardenListEntry>) -> Result<String> {
    let entries: Vec<_> = entries.into_iter().filter(|e| e.id.is_some()).collect();
    let exact: Vec<_> = entries.iter().filter(|e| e.name == name).collect();
    let candidates = if exact.is_empty() {
        let needle = name.to_lowercase();
        entries
            .iter()
            .filter(|e| e.name.to_lowercase().contains(&needle))
            .collect()
    } else {
        exact
    };

    match candidates.as_slice() {
        [] => Err(FnoxError::ProviderSecretNotFound {
            provider: "Bitwarden".to_string(),
            secret: format!("{kind} '{name}'"),
            hint: format!("Check that the {kind} exists and the name is spelled correctly"),
            url: URL.to_string(),
        }),
        [entry] => Ok(entry.id.clone().unwrap()),
        many => Err(FnoxError::ProviderCliFailed {
            provider: "Bitwarden".to_string(),
            details: format!(
                "{} {kind}s match '{name}': {}",
                many.len(),
                many.iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            hint: format!("Use a unique, exact {kind} name"),
            url: URL.to_string(),
        }),
    }
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
        BitwardenProvider::new(None, None, None, None, Some(backend)).unwrap()
    }

    fn provider_with_folder(backend: BitwardenBackend) -> BitwardenProvider {
        BitwardenProvider::new(
            None,
            None,
            None,
            Some("MyApp/Production".to_string()),
            Some(backend),
        )
        .unwrap()
    }

    fn rbw_args(kind: Option<&str>) -> Vec<String> {
        provider_with_folder(BitwardenBackend::Rbw)
            .build_rbw_command(kind, "Database")
            .unwrap()
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn rbw_appends_folder_flag_for_every_field_kind() {
        assert_eq!(
            rbw_args(None),
            ["get", "Database", "--folder", "MyApp/Production"]
        );
        assert_eq!(
            rbw_args(Some("username")),
            [
                "get",
                "Database",
                "--field",
                "username",
                "--folder",
                "MyApp/Production"
            ]
        );
        assert_eq!(
            rbw_args(Some("totp")),
            ["code", "Database", "--folder", "MyApp/Production"]
        );
        assert_eq!(
            rbw_args(Some("API/Key")),
            [
                "get",
                "Database",
                "--field",
                "API/Key",
                "--folder",
                "MyApp/Production"
            ]
        );
    }

    #[test]
    fn rbw_omits_folder_flag_when_unset() {
        let command = provider(BitwardenBackend::Rbw)
            .build_rbw_command(Some("totp"), "Database")
            .unwrap();
        let args: Vec<_> = command.as_std().get_args().collect();

        assert_eq!(args, ["code", "Database"]);
    }

    #[test]
    fn selects_exact_folder_name_over_partial_matches() {
        let json = r#"[
            {"object": "folder", "id": "parent-id", "name": "MyApp"},
            {"object": "folder", "id": "prod-id", "name": "MyApp/Production"},
            {"object": "folder", "id": "prod-old-id", "name": "MyApp/Production-old"}
        ]"#;

        let entries = parse_list_entries("folders", json).unwrap();
        let id = select_entry("folder", "MyApp/Production", entries).unwrap();

        assert_eq!(id, "prod-id");
    }

    #[test]
    fn falls_back_to_single_partial_match() {
        let json = r#"[{"object": "folder", "id": "prod-id", "name": "MyApp/Production"}]"#;

        let entries = parse_list_entries("folders", json).unwrap();
        let id = select_entry("folder", "production", entries).unwrap();

        assert_eq!(id, "prod-id");
    }

    #[test]
    fn ignores_search_results_matched_on_other_fields() {
        let json =
            r#"[{"id": "other-id", "name": "Unrelated", "login": {"username": "database"}}]"#;

        let entries = parse_list_entries("items", json).unwrap();
        let error = select_entry("item", "database", entries).unwrap_err();

        assert!(matches!(error, FnoxError::ProviderSecretNotFound { .. }));
    }

    #[test]
    fn errors_when_folder_not_found() {
        let json = r#"[{"object": "folder", "id": null, "name": "No Folder"}]"#;

        let entries = parse_list_entries("folders", json).unwrap();
        let error = select_entry("folder", "Missing", entries).unwrap_err();

        assert!(matches!(error, FnoxError::ProviderSecretNotFound { .. }));
        assert!(error.to_string().contains("folder 'Missing'"));
    }

    #[test]
    fn errors_when_match_is_ambiguous() {
        let json = r#"[
            {"id": "a", "name": "Database"},
            {"id": "b", "name": "Database"}
        ]"#;

        let entries = parse_list_entries("items", json).unwrap();
        let error = select_entry("item", "Database", entries).unwrap_err();

        assert!(error.to_string().contains("2 items match 'Database'"));
    }

    #[test]
    fn errors_on_invalid_list_json() {
        let error = parse_list_entries("folders", "not json").unwrap_err();

        assert!(matches!(error, FnoxError::ProviderInvalidResponse { .. }));
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
