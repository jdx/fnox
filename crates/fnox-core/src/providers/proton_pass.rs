use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
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
        "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
        "FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN",
        "PROTON_PASS_AGENT_REASON",
        "FNOX_PROTON_PASS_AGENT_REASON",
        "PROTON_PASS_SESSION_DIR",
        "FNOX_PROTON_PASS_SESSION_DIR",
        "PROTON_PASS_KEY_PROVIDER",
        "FNOX_PROTON_PASS_KEY_PROVIDER",
        "PROTON_PASS_ENCRYPTION_KEY",
        "FNOX_PROTON_PASS_ENCRYPTION_KEY",
        "PROTON_PASS_LINUX_KEYRING",
        "FNOX_PROTON_PASS_LINUX_KEYRING",
    ]
}

pub struct ProtonPassProvider {
    vault: Option<String>,
    agent_reason: Option<String>,
}

impl ProtonPassProvider {
    pub fn new(vault: Option<String>, agent_reason: Option<String>) -> Result<Self> {
        Ok(Self {
            vault,
            agent_reason,
        })
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

        for (name, value) in self.pass_cli_env_vars() {
            cmd.env(name, value);
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

            if stderr_lower.contains("proton_pass_agent_reason")
                || stderr_lower.contains("agent reason")
                || stderr_lower.contains("reason must be provided")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Proton Pass".to_string(),
                    details: stderr.trim().to_string(),
                    hint: "Set PROTON_PASS_AGENT_REASON, FNOX_PROTON_PASS_AGENT_REASON, or providers.<name>.agent_reason for audited agent access".to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                });
            }

            if stderr_lower.contains("could not get local key from keyring")
                || stderr_lower.contains("failed to get encryption key")
                || stderr_lower.contains("key provider")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Proton Pass".to_string(),
                    details: stderr.trim().to_string(),
                    hint: "Check Proton Pass session/key storage: PROTON_PASS_SESSION_DIR, PROTON_PASS_KEY_PROVIDER=fs|env|keyring, and PROTON_PASS_ENCRYPTION_KEY".to_string(),
                    url: "https://fnox.jdx.dev/providers/proton-pass".to_string(),
                });
            }

            // Check for authentication-related errors (using CLI-specific patterns)
            if stderr_lower.contains("not logged in")
                || stderr_lower.contains("session expired")
                || stderr_lower.contains("login required")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Proton Pass".to_string(),
                    details: stderr.trim().to_string(),
                    hint: "Run 'pass-cli login', or set PROTON_PASS_PERSONAL_ACCESS_TOKEN and run 'pass-cli login' for PAT/agent access".to_string(),
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

    fn pass_cli_env_vars(&self) -> Vec<(&'static str, String)> {
        let mut env_vars = Vec::new();

        for (target, fnox_name, native_name) in PROTON_PASS_ENV_MAPPINGS {
            if let Some(value) = env_value(fnox_name, native_name) {
                env_vars.push((*target, value));
            }
        }

        if !env_vars
            .iter()
            .any(|(name, _)| *name == "PROTON_PASS_AGENT_REASON")
            && let Some(reason) = self.agent_reason.as_ref().filter(|value| !value.is_empty())
        {
            env_vars.push(("PROTON_PASS_AGENT_REASON", reason.clone()));
        }

        env_vars
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

// Environment variables for Proton Pass authentication.
// Pattern: FNOX_* prefix takes priority, fallback to native pass-cli variables.
const PROTON_PASS_ENV_MAPPINGS: &[(&str, &str, &str)] = &[
    (
        "PROTON_PASS_PASSWORD",
        "FNOX_PROTON_PASS_PASSWORD",
        "PROTON_PASS_PASSWORD",
    ),
    (
        "PROTON_PASS_PASSWORD_FILE",
        "FNOX_PROTON_PASS_PASSWORD_FILE",
        "PROTON_PASS_PASSWORD_FILE",
    ),
    (
        "PROTON_PASS_TOTP",
        "FNOX_PROTON_PASS_TOTP",
        "PROTON_PASS_TOTP",
    ),
    (
        "PROTON_PASS_TOTP_FILE",
        "FNOX_PROTON_PASS_TOTP_FILE",
        "PROTON_PASS_TOTP_FILE",
    ),
    (
        "PROTON_PASS_EXTRA_PASSWORD",
        "FNOX_PROTON_PASS_EXTRA_PASSWORD",
        "PROTON_PASS_EXTRA_PASSWORD",
    ),
    (
        "PROTON_PASS_EXTRA_PASSWORD_FILE",
        "FNOX_PROTON_PASS_EXTRA_PASSWORD_FILE",
        "PROTON_PASS_EXTRA_PASSWORD_FILE",
    ),
    (
        "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
        "FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN",
        "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
    ),
    (
        "PROTON_PASS_AGENT_REASON",
        "FNOX_PROTON_PASS_AGENT_REASON",
        "PROTON_PASS_AGENT_REASON",
    ),
    (
        "PROTON_PASS_SESSION_DIR",
        "FNOX_PROTON_PASS_SESSION_DIR",
        "PROTON_PASS_SESSION_DIR",
    ),
    (
        "PROTON_PASS_KEY_PROVIDER",
        "FNOX_PROTON_PASS_KEY_PROVIDER",
        "PROTON_PASS_KEY_PROVIDER",
    ),
    (
        "PROTON_PASS_ENCRYPTION_KEY",
        "FNOX_PROTON_PASS_ENCRYPTION_KEY",
        "PROTON_PASS_ENCRYPTION_KEY",
    ),
    (
        "PROTON_PASS_LINUX_KEYRING",
        "FNOX_PROTON_PASS_LINUX_KEYRING",
        "PROTON_PASS_LINUX_KEYRING",
    ),
];

fn env_value(fnox_name: &str, native_name: &str) -> Option<String> {
    env::var(fnox_name)
        .or_else(|_| env::var(native_name))
        .ok()
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    static PROTON_PASS_ENV_TEST_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    const PROTON_PASS_TEST_ENV_NAMES: &[&str] = &[
        "FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN",
        "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
        "FNOX_PROTON_PASS_AGENT_REASON",
        "PROTON_PASS_AGENT_REASON",
    ];

    fn with_clean_proton_pass_env<T>(test: impl FnOnce() -> T) -> T {
        let _lock = PROTON_PASS_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_proton_pass_test_env();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));

        clear_proton_pass_test_env();

        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn clear_proton_pass_test_env() {
        for name in PROTON_PASS_TEST_ENV_NAMES {
            env::remove_var(name);
        }
    }

    fn mapped_env_value<'a>(env_vars: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
        env_vars
            .iter()
            .find_map(|(env_name, value)| (*env_name == name).then_some(value.as_str()))
    }

    #[test]
    fn test_provider_metadata_uses_token_aware_login_command() {
        let metadata = include_str!("../../providers/proton-pass.toml");

        assert!(metadata.contains("auth_command = \"pass-cli login\""));
        assert!(!metadata.contains("auth_command = \"pass-cli login --interactive\""));
    }

    #[test]
    fn test_env_value_prefers_fnox_alias_over_native_env() {
        with_clean_proton_pass_env(|| {
            env::set_var("FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN", "fnox-token");
            env::set_var("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "native-token");

            assert_eq!(
                env_value(
                    "FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN",
                    "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
                )
                .as_deref(),
                Some("fnox-token")
            );
        });
    }

    #[test]
    fn test_pass_cli_env_vars_maps_fnox_pat_to_native_env() {
        with_clean_proton_pass_env(|| {
            env::set_var("FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN", "pst_test::key");

            let provider = ProtonPassProvider::new(None, None).unwrap();
            let env_vars = provider.pass_cli_env_vars();

            assert_eq!(
                mapped_env_value(&env_vars, "PROTON_PASS_PERSONAL_ACCESS_TOKEN"),
                Some("pst_test::key")
            );
        });
    }

    #[test]
    fn test_pass_cli_env_vars_uses_provider_agent_reason_when_env_absent() {
        with_clean_proton_pass_env(|| {
            let provider =
                ProtonPassProvider::new(None, Some("fnox secret retrieval".to_string())).unwrap();
            let env_vars = provider.pass_cli_env_vars();

            assert_eq!(
                mapped_env_value(&env_vars, "PROTON_PASS_AGENT_REASON"),
                Some("fnox secret retrieval")
            );
        });
    }

    #[test]
    fn test_pass_cli_env_vars_prefers_env_agent_reason_over_provider_config() {
        with_clean_proton_pass_env(|| {
            env::set_var("FNOX_PROTON_PASS_AGENT_REASON", "env reason");

            let provider =
                ProtonPassProvider::new(None, Some("provider reason".to_string())).unwrap();
            let env_vars = provider.pass_cli_env_vars();

            assert_eq!(
                mapped_env_value(&env_vars, "PROTON_PASS_AGENT_REASON"),
                Some("env reason")
            );
        });
    }

    #[test]
    fn test_pass_cli_env_vars_ignores_empty_provider_agent_reason() {
        with_clean_proton_pass_env(|| {
            let provider = ProtonPassProvider::new(None, Some(String::new())).unwrap();
            let env_vars = provider.pass_cli_env_vars();

            assert_eq!(
                mapped_env_value(&env_vars, "PROTON_PASS_AGENT_REASON"),
                None
            );
        });
    }

    #[test]
    fn test_value_to_reference_passthrough() {
        let provider = ProtonPassProvider::new(Some("vault".to_string()), None).unwrap();
        let result = provider
            .value_to_reference("pass://MyVault/item/password")
            .unwrap();
        assert_eq!(result, "pass://MyVault/item/password");
    }

    #[test]
    fn test_value_to_reference_single_part_with_vault() {
        let provider = ProtonPassProvider::new(Some("TestVault".to_string()), None).unwrap();
        let result = provider.value_to_reference("my-item").unwrap();
        assert_eq!(result, "pass://TestVault/my-item/password");
    }

    #[test]
    fn test_value_to_reference_single_part_without_vault() {
        let provider = ProtonPassProvider::new(None, None).unwrap();
        let result = provider.value_to_reference("my-item");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_two_parts_with_vault() {
        let provider = ProtonPassProvider::new(Some("TestVault".to_string()), None).unwrap();
        let result = provider.value_to_reference("my-item/username").unwrap();
        assert_eq!(result, "pass://TestVault/my-item/username");
    }

    #[test]
    fn test_value_to_reference_three_parts() {
        let provider = ProtonPassProvider::new(None, None).unwrap();
        let result = provider
            .value_to_reference("OtherVault/item/field")
            .unwrap();
        assert_eq!(result, "pass://OtherVault/item/field");
    }

    #[test]
    fn test_value_to_reference_too_many_parts() {
        let provider = ProtonPassProvider::new(Some("vault".to_string()), None).unwrap();
        let result = provider.value_to_reference("a/b/c/d");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_empty() {
        let provider = ProtonPassProvider::new(Some("vault".to_string()), None).unwrap();
        let result = provider.value_to_reference("");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_whitespace_only() {
        let provider = ProtonPassProvider::new(Some("vault".to_string()), None).unwrap();
        let result = provider.value_to_reference("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_invalid_pass_uri_too_few_parts() {
        let provider = ProtonPassProvider::new(None, None).unwrap();
        let result = provider.value_to_reference("pass://vault");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_invalid_pass_uri_empty_parts() {
        let provider = ProtonPassProvider::new(None, None).unwrap();
        let result = provider.value_to_reference("pass://vault//field");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_to_reference_invalid_pass_uri_vault_item_only() {
        let provider = ProtonPassProvider::new(None, None).unwrap();
        let result = provider.value_to_reference("pass://vault/item");
        assert!(result.is_err());
    }

    // id: references are handled in get_secret, not value_to_reference.
    // They use flag-based CLI args since pass:// URIs don't support item IDs.
}
