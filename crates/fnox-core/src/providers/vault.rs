use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use serde_json::json;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const URL: &str = "https://fnox.jdx.dev/providers/vault";
const PROVIDER_NAME: &str = "HashiCorp Vault";

fn parse_secret_reference(value: &str) -> Result<(&str, &str)> {
    match value.split_once('/') {
        None => Ok((value, "value")),
        Some((secret, field))
            if !secret.is_empty() && !field.is_empty() && !field.contains('/') =>
        {
            Ok((secret, field))
        }
        _ => Err(FnoxError::ProviderInvalidResponse {
            provider: PROVIDER_NAME.to_string(),
            details: format!("Invalid secret reference format: '{value}'"),
            hint: "Expected 'secret' or 'secret/field'".to_string(),
            url: URL.to_string(),
        }),
    }
}

fn is_missing_secret_error(error: &FnoxError) -> bool {
    let FnoxError::ProviderCliFailed { details, .. } = error else {
        return false;
    };
    let details = details.to_ascii_lowercase();
    details.contains("no data found") || details.contains("no value found")
}

pub struct HashiCorpVaultProvider {
    address: Option<String>,
    path: Option<String>,
    token: Option<String>,
    namespace: Option<String>,
    credential_command: Option<String>,
}

impl HashiCorpVaultProvider {
    pub fn new(
        address: Option<String>,
        path: Option<String>,
        token: Option<String>,
        namespace: Option<String>,
        credential_command: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            address,
            path,
            token,
            namespace,
            credential_command,
        })
    }

    fn get_secret_path(&self, key: &str) -> String {
        match &self.path {
            Some(path) => format!("{}/{}", path.trim_end_matches('/'), key),
            None => format!("secret/{}", key),
        }
    }

    fn get_address(&self) -> Option<String> {
        self.address.clone().or_else(vault_address)
    }

    async fn get_token(&self, address: &str) -> Result<Option<String>> {
        if let Some(token) = self.token.clone().or_else(vault_token) {
            return Ok(Some(token));
        }

        let Some(command) = &self.credential_command else {
            return Ok(None);
        };

        let namespace = self.namespace.clone().or_else(vault_namespace);
        let mut envs = vec![("VAULT_ADDR", address.to_string())];
        if let Some(namespace) = &namespace {
            envs.push(("VAULT_NAMESPACE", namespace.clone()));
        }

        crate::credential_command::run(
            "HashiCorp Vault",
            command,
            json!({
                "address": address,
                "path": self.path,
                "namespace": namespace,
            }),
            &envs,
            crate::credential_command::DEFAULT_TIMEOUT,
            URL,
        )
        .await
        .map(Some)
    }

    /// Execute vault CLI command with proper authentication
    async fn execute_vault_command(&self, args: &[&str]) -> Result<String> {
        self.execute_vault_command_with_stdin(args, None).await
    }

    /// Execute a vault CLI command, optionally supplying its standard input.
    async fn execute_vault_command_with_stdin(
        &self,
        args: &[&str],
        stdin: Option<&str>,
    ) -> Result<String> {
        tracing::debug!("Executing vault command with args: {:?}", args);

        let mut cmd = Command::new("vault");

        // Set VAULT_ADDR from provider config or environment
        let address = self.get_address().ok_or_else(|| {
            FnoxError::Config(
                "HashiCorp Vault provider address is not configured. Please set it in your provider configuration or via the VAULT_ADDR environment variable.".to_string(),
            )
        })?;

        tracing::debug!("Setting VAULT_ADDR to '{}'", address);
        cmd.env("VAULT_ADDR", &address);

        // Set VAULT_NAMESPACE if provided
        if let Some(namespace) = self.namespace.clone().or_else(vault_namespace) {
            tracing::debug!("Setting VAULT_NAMESPACE to '{}'", namespace);
            cmd.env("VAULT_NAMESPACE", namespace);
        }

        // Set VAULT_TOKEN from provider config or environment
        let token = self
            .get_token(&address)
            .await?
            .ok_or_else(|| FnoxError::ProviderAuthFailed {
                provider: "HashiCorp Vault".to_string(),
                details: "VAULT_TOKEN not set".to_string(),
                hint: "Set VAULT_TOKEN in provider config or environment, or configure credential_command".to_string(),
                url: URL.to_string(),
            })?;

        tracing::debug!(
            "Setting VAULT_TOKEN environment variable (token length: {})",
            token.len()
        );
        cmd.env("VAULT_TOKEN", token);

        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "HashiCorp Vault".to_string(),
                    cli: "vault".to_string(),
                    install_hint: "brew install vault".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "HashiCorp Vault".to_string(),
                    details: e.to_string(),
                    hint: "Check that the Vault CLI is installed and accessible".to_string(),
                    url: URL.to_string(),
                }
            }
        })?;

        if let Some(input) = stdin {
            let mut child_stdin =
                child
                    .stdin
                    .take()
                    .ok_or_else(|| FnoxError::ProviderCliFailed {
                        provider: PROVIDER_NAME.to_string(),
                        details: "Vault child process did not expose piped stdin".to_string(),
                        hint: "This is an internal error".to_string(),
                        url: URL.to_string(),
                    })?;
            child_stdin.write_all(input.as_bytes()).await.map_err(|e| {
                FnoxError::ProviderCliFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details: format!("Failed to write secret to Vault stdin: {e}"),
                    hint: "This is an internal error".to_string(),
                    url: URL.to_string(),
                }
            })?;
            drop(child_stdin);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Failed to wait for Vault command: {e}"),
                hint: "Check your Vault configuration".to_string(),
                url: URL.to_string(),
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
                    url: URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderCliFailed {
                provider: "HashiCorp Vault".to_string(),
                details: stderr_str.to_string(),
                hint: "Check your Vault configuration".to_string(),
                url: URL.to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "HashiCorp Vault".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: URL.to_string(),
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

        let (secret_name, field_name) = parse_secret_reference(value)?;

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

        self.execute_vault_command(&args).await
    }

    async fn test_connection(&self) -> Result<()> {
        let address = self.get_address();
        if let Some(addr) = address {
            tracing::debug!("Testing connection to Vault at {}", addr);
        } else {
            tracing::debug!(
                "Testing connection to Vault (address not specified in config or environment)"
            );
        }

        // Try to get Vault status
        let args = vec!["status"];
        self.execute_vault_command(&args).await?;

        Ok(())
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let (secret_name, field_name) = parse_secret_reference(key)?;
        let secret_path = self.get_secret_path(secret_name);

        tracing::debug!("Writing secret '{}' to HashiCorp Vault", secret_path);

        // Patch explicit fields so updating one value does not replace its siblings.
        // Passing values through stdin prevents Vault from interpreting leading
        // `@` as file input or `-` as an instruction to read uncontrolled stdin.
        let value_arg = format!("{field_name}=-");
        if key.contains('/') {
            let patch_args = vec!["kv", "patch", &secret_path, &value_arg];
            if let Err(error) = self
                .execute_vault_command_with_stdin(&patch_args, Some(value))
                .await
            {
                if !is_missing_secret_error(&error) {
                    return Err(error);
                }
                let put_args = vec!["kv", "put", "-cas=0", &secret_path, &value_arg];
                if self
                    .execute_vault_command_with_stdin(&put_args, Some(value))
                    .await
                    .is_err()
                {
                    // A concurrent writer may have created the secret after the
                    // failed patch. Retry the non-destructive patch in that case.
                    self.execute_vault_command_with_stdin(&patch_args, Some(value))
                        .await?;
                }
            }
        } else {
            let put_args = vec!["kv", "put", &secret_path, &value_arg];
            self.execute_vault_command_with_stdin(&put_args, Some(value))
                .await?;
        }

        tracing::debug!("Successfully wrote secret '{}' to Vault", secret_path);

        // Return the key name to store in config
        Ok(key.to_string())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &[
        "VAULT_TOKEN",
        "FNOX_VAULT_TOKEN",
        "VAULT_ADDR",
        "FNOX_VAULT_ADDR",
        "VAULT_NAMESPACE",
        "FNOX_VAULT_NAMESPACE",
    ]
}

fn vault_token() -> Option<String> {
    env::var("FNOX_VAULT_TOKEN")
        .or_else(|_| env::var("VAULT_TOKEN"))
        .ok()
}

fn vault_address() -> Option<String> {
    env::var("FNOX_VAULT_ADDR")
        .or_else(|_| env::var("VAULT_ADDR"))
        .ok()
}

fn vault_namespace() -> Option<String> {
    env::var("FNOX_VAULT_NAMESPACE")
        .or_else(|_| env::var("VAULT_NAMESPACE"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_secret_references() {
        assert_eq!(
            parse_secret_reference("database").unwrap(),
            ("database", "value")
        );
        assert_eq!(
            parse_secret_reference("database/password").unwrap(),
            ("database", "password")
        );
        assert!(parse_secret_reference("database/nested/password").is_err());
    }

    #[test]
    fn recognizes_missing_secret_errors() {
        let error = FnoxError::ProviderCliFailed {
            provider: PROVIDER_NAME.to_string(),
            details: "No data found at secret/data/database".to_string(),
            hint: String::new(),
            url: URL.to_string(),
        };
        assert!(is_missing_secret_error(&error));

        let error = FnoxError::ProviderCliFailed {
            provider: PROVIDER_NAME.to_string(),
            details: "permission denied".to_string(),
            hint: String::new(),
            url: URL.to_string(),
        };
        assert!(!is_missing_secret_error(&error));
    }
}
