use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::io::Read;
use std::path::PathBuf;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

pub struct AgeEncryptionProvider {
    recipients: Vec<String>,
    key_file: Option<PathBuf>,
}

impl AgeEncryptionProvider {
    pub fn new(recipients: Vec<String>, key_file: Option<String>) -> Self {
        Self {
            recipients,
            key_file: key_file.map(|k| PathBuf::from(shellexpand::tilde(&k).to_string())),
        }
    }
}

#[async_trait]
impl crate::providers::Provider for AgeEncryptionProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String> {
        use std::io::Write;

        if self.recipients.is_empty() {
            return Err(FnoxError::AgeNotConfigured);
        }

        // Parse recipients - try both SSH and native age formats
        let mut parsed_recipients: Vec<Box<dyn age::Recipient + Send + Sync>> = Vec::new();

        for recipient in &self.recipients {
            // Try parsing as SSH recipient first
            if let Ok(ssh_recipient) = recipient.parse::<age::ssh::Recipient>() {
                parsed_recipients.push(Box::new(ssh_recipient));
                continue;
            }

            // Fall back to native age recipient
            match recipient.parse::<age::x25519::Recipient>() {
                Ok(age_recipient) => {
                    parsed_recipients.push(Box::new(age_recipient));
                }
                Err(e) => {
                    return Err(FnoxError::AgeEncryptionFailed {
                        details: format!("Failed to parse recipient '{}': {}", recipient, e),
                    });
                }
            }
        }

        if parsed_recipients.is_empty() {
            return Err(FnoxError::AgeNotConfigured);
        }

        // Create encryptor with parsed recipients
        let encryptor = age::Encryptor::with_recipients(
            parsed_recipients
                .iter()
                .map(|r| r.as_ref() as &dyn age::Recipient),
        )
        .expect("we provided at least one recipient");

        // Encrypt the plaintext
        let mut encrypted = vec![];
        let mut writer =
            encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| FnoxError::AgeEncryptionFailed {
                    details: format!("Failed to create encrypted writer: {}", e),
                })?;

        writer
            .write_all(plaintext.as_bytes())
            .map_err(|e| FnoxError::AgeEncryptionFailed {
                details: format!("Failed to write plaintext: {}", e),
            })?;

        writer
            .finish()
            .map_err(|e| FnoxError::AgeEncryptionFailed {
                details: format!("Failed to finalize encryption: {}", e),
            })?;

        // Base64 encode the encrypted output
        use base64::Engine;
        let encrypted_base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        Ok(encrypted_base64)
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
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

        // Priority for key file:
        // 1. FNOX_AGE_KEY env var (inline key content)
        // 2. self.key_file (from provider config)
        // 3. Settings age_key_file (from CLI flag - deprecated)
        // 4. Default path (~/.config/fnox/age.txt)
        let (identity_content, key_file_path_opt) = if let Some(ref age_key) = *env::FNOX_AGE_KEY {
            // Use the key directly from the environment variable
            (age_key.clone(), None)
        } else {
            // Determine which key file to use
            let key_file_path = if let Some(ref config_key_file) = self.key_file {
                // Use key file from provider config
                config_key_file.clone()
            } else {
                // Get settings which merges CLI flags, env vars, and defaults
                let settings = crate::settings::Settings::get();

                if let Some(ref age_key_file) = settings.age_key_file {
                    // Use age key file from settings (CLI flag or env var - deprecated)
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
