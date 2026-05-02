use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::OnceLock;

use super::hw_encrypt;
use super::yubikey_usb;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

/// Cached HMAC responses keyed by provider name.
/// After a successful YubiKey tap, the response is cached for the process lifetime.
static CACHED_SECRETS: OnceLock<std::sync::Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

#[derive(Clone)]
pub struct YubikeyProvider {
    challenge: Vec<u8>,
    slot: u8,
    provider_name: String,
}

impl YubikeyProvider {
    pub fn new(provider_name: String, challenge: String, slot: String) -> Result<Self> {
        let challenge_bytes = hex::decode(&challenge).map_err(|e| {
            FnoxError::Config(format!(
                "yubikey provider '{}': invalid hex in challenge: {}",
                provider_name, e
            ))
        })?;
        let slot_num: u8 = slot.parse().map_err(|e| {
            FnoxError::Config(format!(
                "yubikey provider '{}': invalid slot number: {}",
                provider_name, e
            ))
        })?;
        Ok(Self {
            challenge: challenge_bytes,
            slot: slot_num,
            provider_name,
        })
    }

    fn get_hmac_secret(&self) -> Result<Vec<u8>> {
        let cache = CACHED_SECRETS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
        // Hold the mutex for the entire operation to prevent concurrent HID access.
        // USB HID devices don't support concurrent access — two callers hitting
        // the device simultaneously would cause a device-busy error.
        let mut guard = cache
            .lock()
            .map_err(|_| FnoxError::Provider("YubiKey cache lock poisoned".to_string()))?;

        if let Some(cached) = guard.get(&self.provider_name) {
            return Ok(cached.clone());
        }

        eprintln!("Tap your YubiKey...");

        let hmac_result = yubikey_usb::challenge_response_hmac(&self.challenge, self.slot)
            .map_err(|e| FnoxError::Provider(format!("YubiKey HMAC-SHA1 challenge failed: {e}")))?;

        let secret = hmac_result.to_vec();
        guard.insert(self.provider_name.clone(), secret.clone());

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
        let provider = self.clone();
        let secret = tokio::task::spawn_blocking(move || provider.get_hmac_secret())
            .await
            .map_err(|e| FnoxError::Provider(format!("YubiKey task failed: {e}")))??;
        hw_encrypt::encrypt(&secret, &self.hkdf_context(), plaintext)
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let provider = self.clone();
        let secret = tokio::task::spawn_blocking(move || provider.get_hmac_secret())
            .await
            .map_err(|e| FnoxError::Provider(format!("YubiKey task failed: {e}")))??;
        hw_encrypt::decrypt(&secret, &self.hkdf_context(), value)
    }
}

/// Setup helpers for `fnox provider add --type yubikey`
pub mod setup {
    use super::yubikey_usb;
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

        // Generate a random 32-byte challenge
        let challenge: [u8; 32] = rand::random();
        let challenge_hex = hex::encode(challenge);

        eprintln!("Tap your YubiKey now...");

        // Verify the YubiKey works with this challenge
        yubikey_usb::challenge_response_hmac(&challenge, slot_num).map_err(|e| {
            FnoxError::Provider(format!(
                "YubiKey HMAC-SHA1 challenge failed: {e}. Make sure HMAC-SHA1 is configured on slot {slot_num}.",
            ))
        })?;

        eprintln!(
            "YubiKey verified successfully for provider '{}'.",
            provider_name
        );

        Ok((challenge_hex, slot_num.to_string()))
    }
}
