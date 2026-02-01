use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::process::Command;

pub struct HashiCorpVaultProvider {
    address: String,
    path: Option<String>,
    token: Option<String>,
    namespace: Option<String>,
}

impl HashiCorpVaultProvider {
    pub fn new(
        address: String,
        path: Option<String>,
        token: Option<String>,
        namespace: Option<String>,
    ) -> Self {
        Self {
            address,
            path,
            token,
            namespace,
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

        // Set VAULT_NAMESPACE if provided
        if let Some(namespace) = &self.namespace {
            tracing::debug!("Setting VAULT_NAMESPACE to '{}'", namespace);
            cmd.env("VAULT_NAMESPACE", namespace);
        }

        // Set VAULT_TOKEN from provider config or environment
        let env_token = vault_token();
        let token = self.token.as_ref().or(env_token.as_ref()).ok_or_else(|| {
            FnoxError::ProviderAuthFailed {
                provider: "HashiCorp Vault".to_string(),
                details: "VAULT_TOKEN not set".to_string(),
                hint: "Set VAULT_TOKEN in provider config or environment".to_string(),
                url: "https://fnox.jdx.dev/providers/vault".to_string(),
            }
        })?;

        tracing::debug!(
            "Setting VAULT_TOKEN environment variable (token length: {})",
            token.len()
        );
        cmd.env("VAULT_TOKEN", token);

        cmd.args(args);

        let output = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "HashiCorp Vault".to_string(),
                    cli: "vault".to_string(),
                    install_hint: "brew install vault".to_string(),
                    url: "https://fnox.jdx.dev/providers/vault".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "HashiCorp Vault".to_string(),
                    details: e.to_string(),
                    hint: "Check that the Vault CLI is installed and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/vault".to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_str = stderr.trim();
            // Check for Vault-specific permission/auth error patterns
            if stderr_str.contains("permission denied")
                || stderr_str.contains("Code: 403")
                || stderr_str.contains("* permission denied")
                || stderr_str.contains("missing client token")
                || stderr_str.contains("token expired")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "HashiCorp Vault".to_string(),
                    details: stderr_str.to_string(),
                    hint: "Check your Vault token has the required permissions".to_string(),
                    url: "https://fnox.jdx.dev/providers/vault".to_string(),
                });
            }
            return Err(FnoxError::ProviderCliFailed {
                provider: "HashiCorp Vault".to_string(),
                details: stderr_str.to_string(),
                hint: "Check your Vault configuration".to_string(),
                url: "https://fnox.jdx.dev/providers/vault".to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "HashiCorp Vault".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: "https://fnox.jdx.dev/providers/vault".to_string(),
            })?;

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
                return Err(FnoxError::ProviderInvalidResponse {
                    provider: "HashiCorp Vault".to_string(),
                    details: format!("Invalid secret reference format: '{}'", value),
                    hint: "Expected 'secret' or 'secret/field'".to_string(),
                    url: "https://fnox.jdx.dev/providers/vault".to_string(),
                });
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

pub fn env_dependencies() -> &'static [&'static str] {
    &["VAULT_TOKEN", "FNOX_VAULT_TOKEN"]
}

fn vault_token() -> Option<String> {
    env::var("FNOX_VAULT_TOKEN")
        .or_else(|_| env::var("VAULT_TOKEN"))
        .ok()
}
