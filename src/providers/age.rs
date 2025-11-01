use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::io::Read;
use std::path::Path;

pub struct AgeEncryptionProvider {
    #[allow(dead_code)]
    recipients: Vec<String>,
}

impl AgeEncryptionProvider {
    pub fn new(recipients: Vec<String>) -> Self {
        Self { recipients }
    }
}

#[async_trait]
impl crate::providers::Provider for AgeEncryptionProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn encrypt(&self, plaintext: &str, _key_file: Option<&Path>) -> Result<String> {
        use std::io::Write;
        use std::process::Command;

        if self.recipients.is_empty() {
            return Err(FnoxError::AgeNotConfigured);
        }

        // Use age CLI to encrypt
        let mut cmd = Command::new("age");

        // Add all recipients
        for recipient in &self.recipients {
            cmd.arg("-r").arg(recipient);
        }

        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                FnoxError::Config(format!(
                    "Failed to spawn age command: {}. Make sure age is installed.",
                    e
                ))
            })?;

        // Write the plaintext to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(plaintext.as_bytes())
                .map_err(|e| FnoxError::Config(format!("Failed to write to age stdin: {}", e)))?;
        }

        // Wait for the command to finish and get output
        let output = child
            .wait_with_output()
            .map_err(|e| FnoxError::Config(format!("Failed to wait for age command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::AgeEncryptionFailed {
                details: stderr.to_string(),
            });
        }

        // Base64 encode the encrypted output
        use base64::Engine;
        let encrypted_base64 = base64::engine::general_purpose::STANDARD.encode(&output.stdout);

        Ok(encrypted_base64)
    }

    async fn get_secret(&self, value: &str, key_file: Option<&Path>) -> Result<String> {
        // value contains the encrypted blob (might be base64 encoded or raw)

        // Try to decode as base64 first, if that fails, treat as raw bytes
        let encrypted_bytes =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value) {
                Ok(bytes) => bytes,
                Err(_) => {
                    // Not base64 encoded, treat as raw bytes
                    value.as_bytes().to_vec()
                }
            };

        // First check if FNOX_AGE_KEY environment variable is set
        let (identity_content, key_file_path_opt) = if let Some(ref age_key) = *env::FNOX_AGE_KEY {
            // Use the key directly from the environment variable
            (age_key.clone(), None)
        } else {
            // Determine which key file to use
            let key_file_path = if let Some(key_file) = key_file {
                // Use provided key file
                key_file.to_path_buf()
            } else {
                // Get settings which merges CLI flags, env vars, and defaults
                let settings = crate::settings::Settings::get();

                if let Some(ref age_key_file) = settings.age_key_file {
                    // Use age key file from settings (CLI flag or env var)
                    age_key_file.clone()
                } else {
                    // Try default path
                    let default_key_path = env::FNOX_CONFIG_DIR.join("age.txt");
                    if !default_key_path.exists() {
                        return Err(FnoxError::AgeIdentityNotFound {
                            path: default_key_path,
                        });
                    }
                    default_key_path
                }
            };

            // Load identity file content
            let content = std::fs::read_to_string(&key_file_path).map_err(|e| {
                FnoxError::AgeIdentityReadFailed {
                    path: key_file_path.clone(),
                    source: e,
                }
            })?;

            (content, Some(key_file_path))
        };

        // Try parsing as SSH identity first, then fall back to age identity file
        let identities = {
            let mut cursor = std::io::Cursor::new(identity_content.as_bytes());

            // First try to parse as SSH identity
            match age::ssh::Identity::from_buffer(
                &mut cursor,
                key_file_path_opt
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string()),
            ) {
                Ok(ssh_identity) => {
                    // SSH identity parsed successfully
                    vec![Box::new(ssh_identity) as Box<dyn age::Identity>]
                }
                Err(_) => {
                    // Not an SSH identity, try age identity file
                    cursor.set_position(0);
                    age::IdentityFile::from_buffer(cursor)
                        .map_err(|e| FnoxError::AgeIdentityParseFailed {
                            details: e.to_string(),
                        })?
                        .into_identities()
                        .map_err(|e| FnoxError::AgeIdentityParseFailed {
                            details: e.to_string(),
                        })?
                }
            }
        };

        let decryptor = age::Decryptor::new(encrypted_bytes.as_slice()).map_err(|e| {
            FnoxError::AgeDecryptionFailed {
                details: format!("Failed to create decryptor: {}", e),
            }
        })?;

        let mut reader = decryptor
            .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
            .map_err(|e| FnoxError::AgeDecryptionFailed {
                details: e.to_string(),
            })?;

        let mut decrypted = vec![];
        reader
            .read_to_end(&mut decrypted)
            .map_err(|e| FnoxError::AgeDecryptionFailed {
                details: format!("Failed to read decrypted data: {}", e),
            })?;

        String::from_utf8(decrypted).map_err(|e| FnoxError::AgeDecryptionFailed {
            details: format!("Failed to decode UTF-8: {}", e),
        })
    }
}
