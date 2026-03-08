use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::OnceLock;

use super::hw_encrypt;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

/// Cached FIDO2 hmac-secret responses keyed by provider name.
static CACHED_SECRETS: OnceLock<std::sync::Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

#[derive(Clone)]
pub struct Fido2Provider {
    credential_id: Vec<u8>,
    salt: Vec<u8>,
    rp_id: String,
    pin: Option<String>,
    provider_name: String,
}

impl Fido2Provider {
    pub fn new(
        provider_name: String,
        credential_id: String,
        salt: String,
        rp_id: String,
        pin: Option<String>,
    ) -> Result<Self> {
        let credential_id_bytes = hex::decode(&credential_id).map_err(|e| {
            FnoxError::Config(format!(
                "fido2 provider '{}': invalid hex in credential_id: {}",
                provider_name, e
            ))
        })?;
        let salt_bytes = hex::decode(&salt).map_err(|e| {
            FnoxError::Config(format!(
                "fido2 provider '{}': invalid hex in salt: {}",
                provider_name, e
            ))
        })?;
        if salt_bytes.len() != 32 {
            return Err(FnoxError::Config(format!(
                "fido2 provider '{}': salt must be exactly 32 bytes (got {})",
                provider_name,
                salt_bytes.len()
            )));
        }
        Ok(Self {
            credential_id: credential_id_bytes,
            salt: salt_bytes,
            rp_id,
            pin,
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
            .map_err(|_| FnoxError::Provider("FIDO2 cache lock poisoned".to_string()))?;

        if let Some(cached) = guard.get(&self.provider_name) {
            return Ok(cached.clone());
        }

        // Resolve PIN: use config value, or prompt interactively
        let pin = if self.pin.is_some() {
            self.pin.clone()
        } else if atty::is(atty::Stream::Stderr) {
            let input = demand::Input::new("FIDO2 PIN (leave empty if not required)")
                .placeholder("")
                .mask_on_submit(true)
                .run()
                .map_err(|e| FnoxError::Provider(format!("Failed to read PIN: {e}")))?;
            if input.is_empty() { None } else { Some(input) }
        } else {
            None
        };

        eprintln!("Touch your FIDO2 key...");

        let device = ctap_hid_fido2::FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())
            .map_err(|e| FnoxError::Provider(format!("Failed to find FIDO2 device: {:?}", e)))?;

        let challenge = ctap_hid_fido2::verifier::create_challenge();

        let mut salt32 = [0u8; 32];
        salt32.copy_from_slice(&self.salt);

        let ext = ctap_hid_fido2::fidokey::AssertionExtension::HmacSecret(Some(salt32));

        let mut builder =
            ctap_hid_fido2::fidokey::GetAssertionArgsBuilder::new(&self.rp_id, &challenge)
                .credential_id(&self.credential_id)
                .extensions(&[ext]);
        if let Some(ref pin) = pin {
            builder = builder.pin(pin);
        }
        let args = builder.build();

        let assertions = device
            .get_assertion_with_args(&args)
            .map_err(|e| FnoxError::Provider(format!("FIDO2 assertion failed: {:?}", e)))?;

        let assertion = assertions
            .first()
            .ok_or_else(|| FnoxError::Provider("FIDO2: no assertion returned".to_string()))?;

        let hmac_secret = assertion
            .extensions
            .iter()
            .find_map(|ext| {
                if let ctap_hid_fido2::fidokey::AssertionExtension::HmacSecret(Some(secret)) = ext {
                    Some(secret.to_vec())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                FnoxError::Provider("FIDO2: hmac-secret not returned by authenticator".to_string())
            })?;

        guard.insert(self.provider_name.clone(), hmac_secret.clone());

        Ok(hmac_secret)
    }

    fn hkdf_context(&self) -> Vec<u8> {
        format!("fnox-fido2-{}", self.provider_name).into_bytes()
    }
}

#[async_trait]
impl crate::providers::Provider for Fido2Provider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String> {
        let provider = self.clone();
        let secret = tokio::task::spawn_blocking(move || provider.get_hmac_secret())
            .await
            .map_err(|e| FnoxError::Provider(format!("FIDO2 task failed: {e}")))??;
        hw_encrypt::encrypt(&secret, &self.hkdf_context(), plaintext)
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let provider = self.clone();
        let secret = tokio::task::spawn_blocking(move || provider.get_hmac_secret())
            .await
            .map_err(|e| FnoxError::Provider(format!("FIDO2 task failed: {e}")))??;
        hw_encrypt::decrypt(&secret, &self.hkdf_context(), value)
    }
}

/// Setup helpers for `fnox provider add --type fido2`
pub mod setup {
    use crate::error::{FnoxError, Result};

    /// Returns (credential_id_hex, salt_hex, rp_id, pin_or_none)
    pub fn setup_fido2(provider_name: &str) -> Result<(String, String, String, Option<String>)> {
        let rp_id = format!("fnox.{}", provider_name);

        eprintln!("\nTouch your FIDO2 key when prompted...");

        let device = ctap_hid_fido2::FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())
            .map_err(|e| FnoxError::Provider(format!("Failed to find FIDO2 device: {:?}", e)))?;

        // Check if PIN is required
        let pin_input = demand::Input::new("FIDO2 PIN (leave empty if not set)")
            .placeholder("")
            .mask_on_submit(true)
            .run()
            .map_err(|e| FnoxError::Config(format!("Failed to read PIN: {}", e)))?;
        let pin: Option<&str> = if pin_input.is_empty() {
            None
        } else {
            Some(&pin_input)
        };
        let pin_to_store = pin.map(|s| s.to_string());

        let challenge = ctap_hid_fido2::verifier::create_challenge();

        let ext = ctap_hid_fido2::fidokey::CredentialExtension::HmacSecret(Some(true));

        eprintln!("Touch your FIDO2 key now...");

        let mut builder =
            ctap_hid_fido2::fidokey::MakeCredentialArgsBuilder::new(&rp_id, &challenge)
                .extensions(&[ext]);
        if let Some(p) = pin {
            builder = builder.pin(p);
        }
        let make_args = builder.build();

        let attestation = device.make_credential_with_args(&make_args).map_err(|e| {
            FnoxError::Provider(format!("FIDO2 credential creation failed: {:?}", e))
        })?;

        // Verify hmac-secret was accepted
        let hmac_ok = attestation.extensions.iter().any(|ext| {
            matches!(
                ext,
                ctap_hid_fido2::fidokey::CredentialExtension::HmacSecret(Some(true))
            )
        });
        if !hmac_ok {
            return Err(FnoxError::Provider(
                "FIDO2 authenticator does not support hmac-secret extension".to_string(),
            ));
        }

        let credential_id = attestation.credential_descriptor.id.clone();
        let credential_id_hex = hex::encode(&credential_id);

        // Generate a random 32-byte salt
        let salt: [u8; 32] = rand::random();
        let salt_hex = hex::encode(salt);

        // Verify the credential works by doing a test assertion
        eprintln!("Touch your FIDO2 key again to verify...");

        let assert_ext = ctap_hid_fido2::fidokey::AssertionExtension::HmacSecret(Some(salt));

        let challenge2 = ctap_hid_fido2::verifier::create_challenge();
        let mut builder2 =
            ctap_hid_fido2::fidokey::GetAssertionArgsBuilder::new(&rp_id, &challenge2)
                .credential_id(&credential_id)
                .extensions(&[assert_ext]);
        if let Some(p) = pin {
            builder2 = builder2.pin(p);
        }
        let get_args = builder2.build();

        let assertions = device.get_assertion_with_args(&get_args).map_err(|e| {
            FnoxError::Provider(format!("FIDO2 verification assertion failed: {:?}", e))
        })?;

        let has_hmac = assertions.first().is_some_and(|a| {
            a.extensions.iter().any(|ext| {
                matches!(
                    ext,
                    ctap_hid_fido2::fidokey::AssertionExtension::HmacSecret(Some(_))
                )
            })
        });

        if !has_hmac {
            return Err(FnoxError::Provider(
                "FIDO2: hmac-secret not returned during verification".to_string(),
            ));
        }

        eprintln!(
            "FIDO2 key verified successfully for provider '{}'.",
            provider_name
        );

        Ok((credential_id_hex, salt_hex, rp_id, pin_to_store))
    }
}
