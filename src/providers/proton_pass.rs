use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::sync::LazyLock;
use tokio::process::Command;

pub fn env_dependencies() -> &'static [&'static str] {
    &[
        "PROTON_PASS_PASSWORD",
        "FNOX_PROTON_PASS_PASSWORD",
        "PROTON_PASS_TOTP",
        "FNOX_PROTON_PASS_TOTP",
        "PROTON_PASS_EXTRA_PASSWORD",
        "FNOX_PROTON_PASS_EXTRA_PASSWORD",
        "PROTON_PASS_PASSWORD_FILE",
        "FNOX_PROTON_PASS_PASSWORD_FILE",
        "PROTON_PASS_TOTP_FILE",
        "FNOX_PROTON_PASS_TOTP_FILE",
        "PROTON_PASS_EXTRA_PASSWORD_FILE",
        "FNOX_PROTON_PASS_EXTRA_PASSWORD_FILE",
    ]
}

pub struct ProtonPassProvider {
    vault: Option<String>,
}

impl ProtonPassProvider {
    pub fn new(vault: Option<String>) -> Self {
        Self { vault }
    }

    /// Convert a value to a pass:// reference
    ///
    /// Reference formats:
    /// - `item` -> `pass://vault/item/password` (requires vault config)
    /// - `item/field` -> `pass://vault/item/field` (requires vault config)
    /// - `id:ITEM_ID` -> `pass://vault/ITEM_ID/password` (requires vault config)
    /// - `id:ITEM_ID/field` -> `pass://vault/ITEM_ID/field` (requires vault config)
    /// - `vault/item/field` -> `pass://vault/item/field`
    /// - `pass://vault/item/field` -> passthrough
    ///
    /// Common fields: `password`, `username`, `email`, `totp`, `url`, `notes`
    /// Field availability depends on the item type.
    ///
    /// Limitation: Alias items are not supported. As of pass-cli v1.5.2, the CLI
    /// does not expose alias email addresses as accessible fields.
    ///
    /// Note: Item or vault names containing `/` must use the full `pass://` format.
    /// Use `id:ITEM_ID` to disambiguate items with duplicate names within a vault.
    ///
    /// The Proton Pass CLI uses SHARE_ID internally, but vault names can be
    /// used directly and are resolved by the CLI.
    fn value_to_reference(&self, value: &str) -> Result<String> {
        // Validate empty values
        let value = value.trim();
        if value.is_empty() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "Proton Pass".to_string(),
                details: "Secret reference cannot be empty".to_string(),
                hint: "Provide an item name, item/field, vault/item/field, or pass:// reference"
                    .to_string(),
                url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
            });
        }

        // Check if value is already a full pass:// reference
        if let Some(path) = value.strip_prefix("pass://") {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
                return Err(FnoxError::ProviderInvalidResponse {
                    provider: "Proton Pass".to_string(),
                    details: format!("Invalid pass:// reference format: '{}'", value),
                    hint: "Expected format: pass://vault/item/field".to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                });
            }
            return Ok(value.to_string());
        }

        let parts: Vec<&str> = value.split('/').collect();
        match parts.len() {
            // item or item/field, requires vault config
            1 | 2 => {
                let vault = self.vault.as_ref().ok_or_else(|| {
                    FnoxError::ProviderInvalidResponse {
                        provider: "Proton Pass".to_string(),
                        details: format!("Unknown vault for secret: '{}'", value),
                        hint: "Specify a vault in the provider config or use a full 'pass://' reference".to_string(),
                        url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                    }
                })?;
                let field = if parts.len() == 1 {
                    "password"
                } else {
                    parts[1]
                };
                Ok(format!("pass://{}/{}/{}", vault, parts[0], field))
            }
            // Three parts: vault/item/field
            3 => Ok(format!("pass://{}/{}/{}", parts[0], parts[1], parts[2])),
            // More than three parts: invalid
            _ => Err(FnoxError::ProviderInvalidResponse {
                provider: "Proton Pass".to_string(),
                details: format!("Invalid secret reference format: '{}'", value),
                hint: "Expected 'item', 'item/field', 'vault/item/field', or 'pass://vault/item/field'".to_string(),
                url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
            }),
        }
    }

    /// Execute pass-cli command with proper authentication environment
    ///
    /// The `secret_ref` parameter is used to provide better error messages for
    /// "not found" errors. Pass `None` for commands that don't reference a secret.
    async fn execute_pass_cli_command(
        &self,
        args: &[&str],
        secret_ref: Option<&str>,
    ) -> Result<String> {
        tracing::debug!("Executing pass-cli command with args: {:?}", args);

        let mut cmd = Command::new("pass-cli");
        cmd.args(args);

        // Pass through Proton Pass environment variables for non-interactive auth
        let env_vars_to_pass = [
            ("PROTON_PASS_PASSWORD", &*PROTON_PASS_PASSWORD),
            ("PROTON_PASS_PASSWORD_FILE", &*PROTON_PASS_PASSWORD_FILE),
            ("PROTON_PASS_TOTP", &*PROTON_PASS_TOTP),
            ("PROTON_PASS_TOTP_FILE", &*PROTON_PASS_TOTP_FILE),
            ("PROTON_PASS_EXTRA_PASSWORD", &*PROTON_PASS_EXTRA_PASSWORD),
            (
                "PROTON_PASS_EXTRA_PASSWORD_FILE",
                &*PROTON_PASS_EXTRA_PASSWORD_FILE,
            ),
        ];
        for (name, value) in env_vars_to_pass {
            if let Some(v) = value {
                cmd.env(name, v);
            }
        }

        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "Proton Pass".to_string(),
                    cli: "pass-cli".to_string(),
                    install_hint:
                        "Download from https://proton.me/pass/download or use your package manager"
                            .to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "Proton Pass".to_string(),
                    details: e.to_string(),
                    hint: "Check that the Proton Pass CLI (pass-cli) is installed and accessible"
                        .to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_lower = stderr.to_lowercase();

            // Check for authentication-related errors (using CLI-specific patterns)
            if stderr_lower.contains("not logged in")
                || stderr_lower.contains("session expired")
                || stderr_lower.contains("login required")
                || stderr_lower.contains("could not get local key from keyring")
                || stderr_lower.contains("failed to get encryption key")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Proton Pass".to_string(),
                    details: stderr.trim().to_string(),
                    hint: "Run 'pass-cli login --interactive' to authenticate".to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                });
            }

            // Check for field not found (e.g., requesting "password" on an alias item)
            if stderr_lower.contains("field does not exist") {
                return Err(FnoxError::ProviderSecretNotFound {
                    provider: "Proton Pass".to_string(),
                    secret: secret_ref.unwrap_or("<unknown>").to_string(),
                    hint: "This item may not have the requested field. Try specifying a different field with 'item/field' syntax".to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                });
            }

            // Check for not found errors
            if stderr_lower.contains("not found") || stderr_lower.contains("does not exist") {
                return Err(FnoxError::ProviderSecretNotFound {
                    provider: "Proton Pass".to_string(),
                    secret: secret_ref.unwrap_or("<unknown>").to_string(),
                    hint: "Check that the vault and item exist in Proton Pass".to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                });
            }

            return Err(FnoxError::ProviderCliFailed {
                provider: "Proton Pass".to_string(),
                details: stderr.trim().to_string(),
                hint: "Check your Proton Pass configuration and authentication".to_string(),
                url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Proton Pass".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for ProtonPassProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Proton Pass", value);

        let value = value.trim();

        // Handle id: references using flag-based CLI args (pass:// URIs don't support item IDs)
        if let Some(id_ref) = value.strip_prefix("id:") {
            let vault = self
                .vault
                .as_ref()
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: "Proton Pass".to_string(),
                    details: format!("Unknown vault for id-based reference: '{}'", value),
                    hint: "Specify a vault in the provider config when using id: references"
                        .to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                })?;
            let (item_id, field) = match id_ref.split_once('/') {
                Some((id, f)) => (id, f),
                None => (id_ref, "password"),
            };
            tracing::debug!(
                "Reading Proton Pass secret by ID: {} field: {}",
                item_id,
                field
            );
            return self
                .execute_pass_cli_command(
                    &[
                        "item",
                        "view",
                        "--vault-name",
                        vault,
                        "--item-id",
                        item_id,
                        "--field",
                        field,
                    ],
                    Some(value),
                )
                .await;
        }

        let reference = self.value_to_reference(value)?;
        tracing::debug!("Reading Proton Pass secret: {}", reference);

        // Use 'pass-cli item view' to fetch the secret
        self.execute_pass_cli_command(&["item", "view", &reference], Some(&reference))
            .await
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Proton Pass");

        // Use 'pass-cli test' for connection testing
        let output = self.execute_pass_cli_command(&["test"], None).await?;

        tracing::debug!("Proton Pass test output: {}", output);

        Ok(())
    }
}

// Environment variables for Proton Pass authentication
// Pattern: FNOX_* prefix takes priority, fallback to native

static PROTON_PASS_PASSWORD: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_PROTON_PASS_PASSWORD")
        .or_else(|_| env::var("PROTON_PASS_PASSWORD"))
        .ok()
});

static PROTON_PASS_PASSWORD_FILE: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_PROTON_PASS_PASSWORD_FILE")
        .or_else(|_| env::var("PROTON_PASS_PASSWORD_FILE"))
        .ok()
});

static PROTON_PASS_TOTP: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_PROTON_PASS_TOTP")
        .or_else(|_| env::var("PROTON_PASS_TOTP"))
        .ok()
});

static PROTON_PASS_TOTP_FILE: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_PROTON_PASS_TOTP_FILE")
        .or_else(|_| env::var("PROTON_PASS_TOTP_FILE"))
        .ok()
});

static PROTON_PASS_EXTRA_PASSWORD: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_PROTON_PASS_EXTRA_PASSWORD")
        .or_else(|_| env::var("PROTON_PASS_EXTRA_PASSWORD"))
        .ok()
});

static PROTON_PASS_EXTRA_PASSWORD_FILE: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_PROTON_PASS_EXTRA_PASSWORD_FILE")
        .or_else(|_| env::var("PROTON_PASS_EXTRA_PASSWORD_FILE"))
        .ok()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_to_reference_passthrough() {
        let provider = ProtonPassProvider::new(Some("vault".to_string()));
        let result = provider
            .value_to_reference("pass://MyVault/item/password")
            .unwrap();
        assert_eq!(result, "pass://MyVault/item/password");
    }

    #[test]
    fn test_value_to_reference_single_part_with_vault() {
        let provider = ProtonPassProvider::new(Some("TestVault".to_string()));
        let result = provider.value_to_reference("my-item").unwrap();
        assert_eq!(result, "pass://TestVault/my-item/password");
    }

    #[test]
    fn test_value_to_reference_single_part_without_vault() {
        let provider = ProtonPassProvider::new(None);
        let result = provider.value_to_reference("my-item");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_two_parts_with_vault() {
        let provider = ProtonPassProvider::new(Some("TestVault".to_string()));
        let result = provider.value_to_reference("my-item/username").unwrap();
        assert_eq!(result, "pass://TestVault/my-item/username");
    }

    #[test]
    fn test_value_to_reference_three_parts() {
        let provider = ProtonPassProvider::new(None);
        let result = provider
            .value_to_reference("OtherVault/item/field")
            .unwrap();
        assert_eq!(result, "pass://OtherVault/item/field");
    }

    #[test]
    fn test_value_to_reference_too_many_parts() {
        let provider = ProtonPassProvider::new(Some("vault".to_string()));
        let result = provider.value_to_reference("a/b/c/d");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_empty() {
        let provider = ProtonPassProvider::new(Some("vault".to_string()));
        let result = provider.value_to_reference("");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_whitespace_only() {
        let provider = ProtonPassProvider::new(Some("vault".to_string()));
        let result = provider.value_to_reference("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_invalid_pass_uri_too_few_parts() {
        let provider = ProtonPassProvider::new(None);
        let result = provider.value_to_reference("pass://vault");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_invalid_pass_uri_empty_parts() {
        let provider = ProtonPassProvider::new(None);
        let result = provider.value_to_reference("pass://vault//field");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_invalid_pass_uri_vault_item_only() {
        let provider = ProtonPassProvider::new(None);
        let result = provider.value_to_reference("pass://vault/item");
        assert!(result.is_err());
    }

    // id: references are handled in get_secret, not value_to_reference.
    // They use flag-based CLI args since pass:// URIs don't support item IDs.
}
