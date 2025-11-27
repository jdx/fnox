use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::{WizardCategory, WizardField, WizardInfo};
use async_trait::async_trait;
use std::process::Command;
use std::sync::LazyLock;

pub const WIZARD_INFO: WizardInfo = WizardInfo {
    provider_type: "vault",
    display_name: "HashiCorp Vault",
    description: "HashiCorp Vault",
    category: WizardCategory::CloudSecretsManager,
    setup_instructions: "\
Stores secrets in HashiCorp Vault.
Requires Vault address and token.",
    default_name: "vault",
    fields: &[
        WizardField {
            name: "address",
            label: "Vault address:",
            placeholder: "https://vault.example.com:8200",
            required: true,
        },
        WizardField {
            name: "path",
            label: "Vault path prefix (optional):",
            placeholder: "secret/data/fnox",
            required: false,
        },
        WizardField {
            name: "token",
            label: "Vault token (optional, can use VAULT_TOKEN env var):",
            placeholder: "",
            required: false,
        },
    ],
};

pub struct HashiCorpVaultProvider {
    address: String,
    path: Option<String>,
    token: Option<String>,
}

impl HashiCorpVaultProvider {
    pub fn new(address: String, path: Option<String>, token: Option<String>) -> Self {
        Self {
            address,
            path,
            token,
        }
    }

    fn get_secret_path(&self, key: &str) -> String {
        match &self.path {
            Some(path) => format!("{}/{}", path.trim_end_matches('/'), key),
            None => format!("secret/{}", key),
        }
    }

    /// Execute vault CLI command with proper authentication
    fn execute_vault_command(&self, args: &[&str]) -> Result<String> {
        tracing::debug!("Executing vault command with args: {:?}", args);

        let mut cmd = Command::new("vault");

        // Set VAULT_ADDR from provider config
        cmd.env("VAULT_ADDR", &self.address);

        // Set VAULT_TOKEN from provider config or environment
        let token = self
            .token
            .as_ref()
            .or(VAULT_TOKEN.as_ref())
            .ok_or_else(|| {
                FnoxError::Provider(
                    "VAULT_TOKEN not set. Set it in provider config or environment.".to_string(),
                )
            })?;

        tracing::debug!(
            "Setting VAULT_TOKEN environment variable (token length: {})",
            token.len()
        );
        cmd.env("VAULT_TOKEN", token);

        cmd.args(args);

        let output = cmd.output().map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to execute 'vault' command: {}. Make sure the Vault CLI is installed.",
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::Provider(format!(
                "Vault CLI command failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| FnoxError::Provider(format!("Invalid UTF-8 in command output: {}", e)))?;

        Ok(stdout.trim().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for HashiCorpVaultProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from HashiCorp Vault", value);

        // Parse value as "secret-name/field" or just "secret-name"
        // Default field is "value" if not specified (Vault KV v2 convention)
        let parts: Vec<&str> = value.split('/').collect();

        let (secret_name, field_name) = match parts.len() {
            1 => (parts[0], "value"),
            2 => (parts[0], parts[1]),
            _ => {
                return Err(FnoxError::Provider(format!(
                    "Invalid secret reference format: '{}'. Expected 'secret' or 'secret/field'",
                    value
                )));
            }
        };

        let secret_path = self.get_secret_path(secret_name);

        tracing::debug!(
            "Reading Vault secret '{}' field '{}'",
            secret_path,
            field_name
        );

        // Build the vault kv get command
        // vault kv get -field=<field> <path>
        let field_arg = format!("-field={}", field_name);
        let args = vec!["kv", "get", &field_arg, &secret_path];

        self.execute_vault_command(&args)
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Vault at {}", self.address);

        // Try to get Vault status
        let args = vec!["status"];
        self.execute_vault_command(&args)?;

        Ok(())
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let secret_path = self.get_secret_path(key);

        tracing::debug!("Writing secret '{}' to HashiCorp Vault", secret_path);

        // Use vault kv put command: vault kv put <path> value=<value>
        let value_arg = format!("value={}", value);
        let args = vec!["kv", "put", &secret_path, &value_arg];

        self.execute_vault_command(&args)?;

        tracing::debug!("Successfully wrote secret '{}' to Vault", secret_path);

        // Return the key name to store in config
        Ok(key.to_string())
    }
}

static VAULT_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_VAULT_TOKEN")
        .or_else(|_| env::var("VAULT_TOKEN"))
        .ok()
});
