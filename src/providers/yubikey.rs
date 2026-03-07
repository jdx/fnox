use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::OnceLock;

use super::hw_encrypt;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

/// Cached HMAC responses keyed by provider name.
/// After a successful YubiKey tap, the response is cached for the process lifetime.
static CACHED_SECRETS: OnceLock<std::sync::Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

pub struct YubikeyProvider {
    challenge: Vec<u8>,
    slot: u8,
    provider_name: String,
}

impl YubikeyProvider {
    pub fn new(challenge: String, slot: String) -> Self {
        Self::with_name("yubikey".to_string(), challenge, slot)
    }

    pub fn with_name(provider_name: String, challenge: String, slot: String) -> Self {
        let challenge_bytes = hex::decode(&challenge).unwrap_or_default();
        let slot_num: u8 = slot.parse().unwrap_or(2);
        Self {
            challenge: challenge_bytes,
            slot: slot_num,
            provider_name,
        }
    }

    fn get_hmac_secret(&self) -> Result<Vec<u8>> {
        let cache = CACHED_SECRETS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
        if let Ok(guard) = cache.lock()
            && let Some(cached) = guard.get(&self.provider_name)
        {
            return Ok(cached.clone());
        }

        eprintln!("Tap your YubiKey...");

        let mut yk = yubico_manager::Yubico::new();
        let device = yk
            .find_yubikey()
            .map_err(|e| FnoxError::Provider(format!("Failed to find YubiKey: {:?}", e)))?;

        let slot = match self.slot {
            1 => yubico_manager::config::Slot::Slot1,
            _ => yubico_manager::config::Slot::Slot2,
        };
        let command = match self.slot {
            1 => yubico_manager::config::Command::ChallengeHmac1,
            _ => yubico_manager::config::Command::ChallengeHmac2,
        };
        let yk_conf = yubico_manager::config::Config {
            product_id: device.product_id,
            vendor_id: device.vendor_id,
            variable: false,
            slot,
            mode: yubico_manager::config::Mode::Sha1,
            command,
        };

        let hmac_result = yk
            .challenge_response_hmac(&self.challenge, yk_conf)
            .map_err(|e| {
                FnoxError::Provider(format!("YubiKey HMAC-SHA1 challenge failed: {:?}", e))
            })?;

        let secret = hmac_result.to_vec();

        if let Ok(mut guard) = cache.lock() {
            guard.insert(self.provider_name.clone(), secret.clone());
        }

        Ok(secret)
    }

    fn hkdf_context(&self) -> Vec<u8> {
        format!("fnox-yubikey-{}", self.provider_name).into_bytes()
    }
}

#[async_trait]
impl crate::providers::Provider for YubikeyProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String> {
        let secret = self.get_hmac_secret()?;
        hw_encrypt::encrypt(&secret, &self.hkdf_context(), plaintext)
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let secret = self.get_hmac_secret()?;
        hw_encrypt::decrypt(&secret, &self.hkdf_context(), value)
    }
}

/// Setup helpers for `fnox provider add --type yubikey`
pub mod setup {
    use crate::error::{FnoxError, Result};

    pub fn setup_yubikey(provider_name: &str) -> Result<(String, String)> {
        eprintln!("\nPlug in your YubiKey and tap it when prompted...");

        let slot_str = demand::Input::new("YubiKey slot (1 or 2, default: 2)")
            .placeholder("2")
            .run()
            .map_err(|e| FnoxError::Config(format!("Failed to read slot: {}", e)))?;
        let slot_num: u8 = if slot_str.is_empty() {
            2
        } else {
            slot_str
                .parse()
                .map_err(|_| FnoxError::Config("Slot must be 1 or 2".to_string()))?
        };

        if slot_num != 1 && slot_num != 2 {
            return Err(FnoxError::Config("Slot must be 1 or 2".to_string()));
        }

        // Generate a random challenge
        let challenge = {
            let random_identity = age::x25519::Identity::generate();
            let hash = blake3::hash(
                age::secrecy::ExposeSecret::expose_secret(&random_identity.to_string()).as_bytes(),
            );
            hash.as_bytes()[..32].to_vec()
        };
        let challenge_hex = hex::encode(&challenge);

        eprintln!("Tap your YubiKey now...");

        // Verify the YubiKey works with this challenge
        let mut yk = yubico_manager::Yubico::new();
        let device = yk
            .find_yubikey()
            .map_err(|e| FnoxError::Provider(format!("Failed to find YubiKey: {:?}", e)))?;

        let slot = match slot_num {
            1 => yubico_manager::config::Slot::Slot1,
            _ => yubico_manager::config::Slot::Slot2,
        };
        let command = match slot_num {
            1 => yubico_manager::config::Command::ChallengeHmac1,
            _ => yubico_manager::config::Command::ChallengeHmac2,
        };
        let yk_conf = yubico_manager::config::Config {
            product_id: device.product_id,
            vendor_id: device.vendor_id,
            variable: false,
            slot,
            mode: yubico_manager::config::Mode::Sha1,
            command,
        };

        let _ = yk
            .challenge_response_hmac(&challenge, yk_conf)
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "YubiKey HMAC-SHA1 challenge failed: {:?}. Make sure HMAC-SHA1 is configured on slot {}.",
                    e, slot_num
                ))
            })?;

        eprintln!(
            "YubiKey verified successfully for provider '{}'.",
            provider_name
        );

        Ok((challenge_hex, slot_num.to_string()))
    }
}
