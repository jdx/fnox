use crate::commands::Cli;
use crate::config::{Config, SecretValue};
use crate::encryption::age_encryption::AgeEncryptor;
use crate::error::{FnoxError, Result};
use clap::Args;
use std::collections::HashMap;

#[derive(Debug, Args)]
pub struct EncryptCommand {
    /// Key to use for encryption
    #[arg(short, long)]
    pub key: Option<String>,
}

impl EncryptCommand {
    pub async fn run(&self, cli: &Cli, mut config: Config) -> Result<()> {
        tracing::debug!("Encrypting configuration file");

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

        // Check if already encrypted
        if encryption_config.encrypted_data.is_some() {
            println!("Configuration is already encrypted.");
            return Ok(());
        }

        // Get recipients
        let recipients = if encryption_config.recipients.is_empty() {
            return Err(FnoxError::AgeNotConfigured);
        } else {
            encryption_config.recipients.clone()
        };

        tracing::debug!("Encrypting for {} recipients", recipients.len());

        // Create encryptor
        let encryptor = AgeEncryptor::new(recipients).map_err(|e| {
            FnoxError::AgeEncryptionFailed {
                details: format!("Failed to create encryptor: {}", e),
            }
        })?;

        // Serialize secrets to JSON
        let secrets_json = serde_json::to_string(&config.secrets)?;
        let plaintext = secrets_json.as_bytes();

        // Encrypt the data
        let ciphertext = encryptor.encrypt(plaintext).await.map_err(|e| {
            FnoxError::AgeEncryptionFailed {
                details: e.to_string(),
            }
        })?;

        // Base64 encode the ciphertext
        use base64::Engine;
        let encrypted_data = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

        // Update config
        if let Some(enc_config) = &mut config.encryption {
            enc_config.encrypted_data = Some(encrypted_data);
        }

        // Clear plaintext secrets
        config.secrets = HashMap::new();

        // Save config
        config.save(&cli.config)?;

        println!("✓ Configuration encrypted successfully");
        println!("  Encrypted {} secret(s)", serde_json::from_str::<HashMap<String, SecretValue>>(&secrets_json)?.len());

        Ok(())
    }
}
