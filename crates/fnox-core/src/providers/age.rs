use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::OptionProviderSecretRef;
use async_trait::async_trait;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

pub struct AgeEncryptionProvider {
    recipients: Vec<String>,
    key_file: Option<PathBuf>,
    identity: OptionProviderSecretRef,
    config: Option<Arc<crate::config::Config>>,
    profile: String,
    provider_name: String,
    identity_cycle_guard: Option<AgeIdentityCycleGuard>,
}

impl AgeEncryptionProvider {
    pub fn new(
        recipients: Vec<String>,
        key_file: Option<String>,
        identity: OptionProviderSecretRef,
    ) -> Result<Self> {
        Ok(Self {
            recipients,
            key_file: key_file.map(|k| PathBuf::from(shellexpand::tilde(&k).to_string())),
            identity,
            config: None,
            profile: "default".to_string(),
            provider_name: "age".to_string(),
            identity_cycle_guard: None,
        })
    }

    pub fn new_with_config(
        recipients: Vec<String>,
        key_file: Option<String>,
        identity: OptionProviderSecretRef,
        config: Arc<crate::config::Config>,
        profile: String,
        provider_name: String,
        identity_cycle_guard: Option<AgeIdentityCycleGuard>,
    ) -> Result<Self> {
        Ok(Self {
            recipients,
            key_file: key_file.map(|k| PathBuf::from(shellexpand::tilde(&k).to_string())),
            identity,
            config: Some(config),
            profile,
            provider_name,
            identity_cycle_guard,
        })
    }

    async fn resolve_provider_identity(&self) -> Result<Option<String>> {
        let Some(identity) = self.identity.as_ref() else {
            return Ok(None);
        };

        if identity.provider == self.provider_name {
            return Err(FnoxError::ProviderConfigCycle {
                provider: self.provider_name.clone(),
                cycle: format!("{} -> {}", self.provider_name, identity.provider),
            });
        }

        let Some(config) = self.config.as_ref() else {
            return Err(FnoxError::Config(
                "Cannot resolve age identity provider reference without config context".to_string(),
            ));
        };

        let identity_cycle_guard = self.identity_cycle_guard.clone().unwrap_or_default();
        let _guard = identity_cycle_guard.enter(&self.provider_name)?;
        let mut ctx = crate::providers::resolver::ResolutionContext::new();
        crate::providers::resolver::resolve_provider_ref_with_identity_cycle_guard(
            config,
            &self.profile,
            &self.identity,
            &mut ctx,
            identity_cycle_guard,
        )
        .await
    }
}

#[derive(Clone, Default)]
pub struct AgeIdentityCycleGuard {
    resolving: Arc<Mutex<Vec<String>>>,
}

impl AgeIdentityCycleGuard {
    fn enter(&self, provider_name: &str) -> Result<AgeIdentityCycleEntry> {
        let mut resolving = self
            .resolving
            .lock()
            .map_err(|_| FnoxError::Config("Age identity cycle guard lock poisoned".to_string()))?;

        if let Some(start) = resolving.iter().position(|name| name == provider_name) {
            let mut cycle = resolving[start..].to_vec();
            cycle.push(provider_name.to_string());
            return Err(FnoxError::ProviderConfigCycle {
                provider: provider_name.to_string(),
                cycle: cycle.join(" -> "),
            });
        }

        resolving.push(provider_name.to_string());

        Ok(AgeIdentityCycleEntry {
            provider_name: provider_name.to_string(),
            resolving: self.resolving.clone(),
        })
    }
}

struct AgeIdentityCycleEntry {
    provider_name: String,
    resolving: Arc<Mutex<Vec<String>>>,
}

impl Drop for AgeIdentityCycleEntry {
    fn drop(&mut self) {
        if let Ok(mut resolving) = self.resolving.lock()
            && let Some(index) = resolving
                .iter()
                .rposition(|name| name == &self.provider_name)
        {
            resolving.remove(index);
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

        // Parse recipients - try SSH, native age, then plugin formats
        let mut parsed_recipients: Vec<Box<dyn age::Recipient + Send + Sync>> = Vec::new();
        let mut plugin_recipients: Vec<age::plugin::Recipient> = Vec::new();

        for recipient in &self.recipients {
            // Try parsing as SSH recipient first
            if let Ok(ssh_recipient) = recipient.parse::<age::ssh::Recipient>() {
                parsed_recipients.push(Box::new(ssh_recipient));
                continue;
            }

            // Try native age recipient
            if let Ok(age_recipient) = recipient.parse::<age::x25519::Recipient>() {
                parsed_recipients.push(Box::new(age_recipient));
                continue;
            }

            // Fall back to plugin recipient, e.g. age-plugin-yubikey: age1yubikey1...
            match recipient.parse::<age::plugin::Recipient>() {
                Ok(plugin_recipient) => plugin_recipients.push(plugin_recipient),
                Err(e) => {
                    return Err(FnoxError::AgeEncryptionFailed {
                        details: format!("Failed to parse recipient '{}': {}", recipient, e),
                    });
                }
            }
        }

        // Build one plugin driver per distinct plugin name. RecipientPluginV1
        // filters the recipient list by plugin name internally, so we pass the
        // full list and spawn the matching `age-plugin-*` binary from $PATH.
        let plugin_names: std::collections::BTreeSet<String> = plugin_recipients
            .iter()
            .map(|r| r.plugin().to_string())
            .collect();
        for plugin_name in plugin_names {
            let plugin = age::plugin::RecipientPluginV1::new(
                &plugin_name,
                &plugin_recipients,
                &[],
                age::cli_common::UiCallbacks,
            )
            .map_err(|e| FnoxError::AgeEncryptionFailed {
                details: format!(
                    "Failed to initialize age plugin 'age-plugin-{}' \
                     (is it installed and on your PATH?): {}",
                    plugin_name, e
                ),
            })?;
            parsed_recipients.push(Box::new(plugin));
        }

        // Every recipient is parsed into `parsed_recipients` (directly or via a
        // plugin driver) or returns early on failure, and the empty-input case
        // is rejected at the top of the function, so this is always non-empty.
        debug_assert!(
            !parsed_recipients.is_empty(),
            "non-empty recipients must yield at least one parsed recipient"
        );

        // Create encryptor with parsed recipients. With plugin recipients this
        // talks to the plugin binary eagerly, so it can fail for reasons beyond
        // an empty recipient list (which we already ruled out above).
        let encryptor = age::Encryptor::with_recipients(
            parsed_recipients
                .iter()
                .map(|r| r.as_ref() as &dyn age::Recipient),
        )
        .map_err(|e| FnoxError::AgeEncryptionFailed {
            details: format!("Failed to initialize age encryptor: {}", e),
        })?;

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

        // Priority for identity:
        // 1. FNOX_AGE_KEY env var (inline key content)
        // 2. self.identity (from provider config, resolved from another provider)
        // 3. self.key_file (from provider config)
        // 4. Settings age_key_file (from CLI flag - deprecated)
        // 5. Default path (~/.config/fnox/age.txt)
        let (identity_content, key_file_path_opt) = if let Some(ref age_key) = *env::FNOX_AGE_KEY {
            // Use the key directly from the environment variable
            (age_key.clone(), None)
        } else if let Some(identity) = self.resolve_provider_identity().await? {
            (identity, None)
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
                    // Not an SSH identity, try age identity file. Setting
                    // callbacks lets `into_identities` construct plugin
                    // identities (e.g. AGE-PLUGIN-YUBIKEY-1...) by driving the
                    // matching `age-plugin-*` binary for PIN/touch prompts.
                    cursor.set_position(0);
                    age::IdentityFile::from_buffer(cursor)
                        .map_err(|e| FnoxError::AgeIdentityParseFailed {
                            details: e.to_string(),
                        })?
                        .with_callbacks(age::cli_common::UiCallbacks)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;

    /// Regression test for the "incorrect HRP" failure on age plugin recipients
    /// (e.g. age-plugin-yubikey). A plugin recipient must now be recognized and
    /// dispatched to the plugin driver instead of being rejected by the native
    /// x25519 parser. This holds whether or not the plugin binary is installed:
    /// if it is, wrapping may succeed; if it isn't, the error is about the
    /// missing plugin binary -- never about an "incorrect HRP" / parse failure.
    #[tokio::test]
    async fn plugin_recipient_is_not_rejected_as_invalid_hrp() {
        let recipient =
            "age1yubikey1qwla8v7cu3mx6mp79asgrh5ad2h52flwln7c66ydcyy50lg5uh0gxh4kmaz".to_string();
        let provider =
            AgeEncryptionProvider::new(vec![recipient], None, OptionProviderSecretRef::none())
                .expect("provider construction should succeed");

        if let Err(err) = provider.encrypt("plaintext").await {
            let message = err.to_string();
            assert!(
                !message.contains("incorrect HRP"),
                "plugin recipient should not be rejected by the native parser: {message}"
            );
            assert!(
                !message.contains("Failed to parse recipient"),
                "plugin recipient should parse successfully: {message}"
            );
        }
    }
}
