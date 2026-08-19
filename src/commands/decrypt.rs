use crate::commands::Cli;
use crate::config::{Config, SecretValue};
use crate::encryption::age_encryption::AgeEncryptor;
use crate::env;
use crate::error::{FnoxError, Result};
use clap::Args;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, usage_derive::Args)]
pub struct DecryptCommand {
    /// Key to use for decryption
    #[usage(short, long)]
    pub key: Option<String>,
}

impl DecryptCommand {
    pub async fn run(&self, cli: &Cli, mut config: Config) -> Result<()> {
        tracing::debug!("Decrypting configuration file");

        if config.encryption.is_none() {
            return Err(FnoxError::EncryptionNotConfigured);
        }

        let encryption_config = config.encryption.as_ref().unwrap();
        tracing::debug!("Using encryption type: {}", encryption_config.key_type);

        if encryption_config.key_type != "age" {
            return Err(FnoxError::UnsupportedEncryptionType {
                encryption_type: encryption_config.key_type.clone(),
            });
        }

        if encryption_config.encrypted_data.is_none() {
            println!("No encrypted data found. Configuration may already be decrypted.");
            return Ok(());
        }

        // Determine identity file path
        let identity_path = if let Some(ref key_path) = self.key {
            key_path.clone()
        } else if let Some(env_key) = (*env::FNOX_AGE_KEY).clone() {
            // If FNOX_AGE_KEY is set, write it to a temp file
            let temp_dir = env::temp_dir();
            let temp_key_path = temp_dir.join("fnox_age_key.txt");
            std::fs::write(&temp_key_path, env_key)?;
            temp_key_path.to_string_lossy().to_string()
        } else {
            // Default to ~/.config/fnox/age.txt
            let default_key = env::FNOX_CONFIG_DIR.join("age.txt");

            if !default_key.exists() {
                // Try SSH key as fallback
                let ssh_key = env::HOME_DIR
                    .join(".ssh")
                    .join("id_ed25519");

                if ssh_key.exists() {
                    tracing::debug!("Using SSH key for decryption");
                    let decryptor = AgeEncryptor::from_ssh_key(&ssh_key).map_err(|e| {
                        FnoxError::AgeIdentityReadFailed {
                            path: ssh_key.clone(),
                            source: e,
                        }
                    })?;

                    return self.decrypt_with_encryptor(cli, config, decryptor).await;
                }

                return Err(FnoxError::AgeIdentityNotFound {
                    path: default_key,
                });
            }

            default_key.to_string_lossy().to_string()
        };

        tracing::debug!("Using identity file: {}", identity_path);

        // Create decryptor
        let decryptor = AgeEncryptor::from_identity_file(&identity_path).map_err(|e| {
            FnoxError::AgeIdentityReadFailed {
                path: PathBuf::from(&identity_path),
                source: e,
            }
        })?;

        self.decrypt_with_encryptor(cli, config, decryptor).await
    }

    async fn decrypt_with_encryptor(
        &self,
        cli: &Cli,
        mut config: Config,
        decryptor: AgeEncryptor,
    ) -> Result<()> {
        let encryption_config = config.encryption.as_ref().unwrap();
        let encrypted_data = encryption_config.encrypted_data.as_ref().unwrap();

        // Base64 decode
        use base64::Engine;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(encrypted_data)
            .map_err(|e| FnoxError::AgeDecryptionFailed {
                details: format!("Failed to decode encrypted data: {}", e),
            })?;

        // Decrypt
        let plaintext = decryptor.decrypt(&ciphertext).await.map_err(|e| {
            FnoxError::AgeDecryptionFailed {
                details: e.to_string(),
            }
        })?;

        // Deserialize secrets
        let secrets: HashMap<String, SecretValue> =
            serde_json::from_slice(&plaintext).map_err(|e| FnoxError::AgeDecryptionFailed {
                details: format!("Failed to parse decrypted data: {}", e),
            })?;

        let secret_count = secrets.len();

        // Update config
        config.secrets = secrets;

        // Clear encrypted data
        if let Some(enc_config) = &mut config.encryption {
            enc_config.encrypted_data = None;
        }

        // Save config
        config.save(&cli.config)?;

        println!("✓ Configuration decrypted successfully");
        println!("  Decrypted {} secret(s)", secret_count);

        Ok(())
    }
}
