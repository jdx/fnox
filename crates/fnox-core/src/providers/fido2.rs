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

fn batch_errors(secrets: &[(String, String)], message: &str) -> HashMap<String, Result<String>> {
    secrets
        .iter()
        .map(|(key, _)| (key.clone(), Err(FnoxError::Provider(message.to_string()))))
        .collect()
}

fn decrypt_batch(
    secrets: &[(String, String)],
    secret: &[u8],
    context: &[u8],
) -> HashMap<String, Result<String>> {
    secrets
        .iter()
        .map(|(key, value)| (key.clone(), hw_encrypt::decrypt(secret, context, value)))
        .collect()
}

/// How the key verifies the user before releasing the hmac-secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verification {
    /// Built-in user verification, such as a fingerprint sensor.
    Biometric,
    /// A PIN is set and must be entered.
    Pin,
    /// Neither is configured; touching the key is enough.
    TouchOnly,
}

/// Works out the verification the key expects from its CTAP `getInfo` options.
/// `uv` means built-in verification is set up; `clientPin` means a PIN is set.
fn verification_for(options: &[(String, bool)]) -> Verification {
    let flag = |name: &str| options.iter().find(|(key, _)| key == name).map(|(_, v)| *v);
    if flag("uv") == Some(true) {
        Verification::Biometric
    } else if flag("clientPin") == Some(true) {
        Verification::Pin
    } else {
        Verification::TouchOnly
    }
}

fn read_pin(prompt: &str) -> Result<String> {
    demand::Input::new(prompt)
        .placeholder("")
        .password(true)
        .run()
        .map_err(|e| FnoxError::Provider(format!("Failed to read PIN: {e}")))
}

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

        // Discover the device before prompting so device-count errors are shown
        // without asking for a PIN that cannot be used.
        let device = ctap_hid_fido2::FidoKeyHidFactory::create(
            &ctap_hid_fido2::Cfg::init().with_keep_alive_msg_to_stderr(true),
        )
        .map_err(|e| FnoxError::Provider(format!("Failed to find FIDO2 device: {:?}", e)))?;

        let is_tty = atty::is(atty::Stream::Stderr);
        // Older keys may not answer getInfo; fall back to asking for an optional PIN.
        let verification = device
            .get_info()
            .ok()
            .map(|info| verification_for(&info.options));

        let hmac_secret = if let Some(pin) = self.pin.as_deref() {
            eprintln!("Touch your FIDO2 key...");
            self.assert_hmac_secret(&device, Some(pin))?
        } else {
            match verification {
                Some(Verification::Biometric) => {
                    eprintln!("Verify with your FIDO2 key's fingerprint sensor...");
                    match self.assert_hmac_secret(&device, None) {
                        Ok(secret) => secret,
                        // A failed or exhausted fingerprint read can still be
                        // satisfied with the PIN, if the key has one.
                        Err(error) if is_tty => {
                            eprintln!("Fingerprint verification failed: {error}");
                            let pin = read_pin("FIDO2 PIN (leave empty to cancel)")?;
                            if pin.is_empty() {
                                return Err(error);
                            }
                            self.assert_hmac_secret(&device, Some(&pin))?
                        }
                        Err(error) => return Err(error),
                    }
                }
                Some(Verification::Pin) if is_tty => {
                    let pin = read_pin("FIDO2 PIN")?;
                    eprintln!("Touch your FIDO2 key...");
                    self.assert_hmac_secret(&device, Some(&pin))?
                }
                Some(Verification::Pin) => {
                    return Err(FnoxError::Provider(format!(
                        "FIDO2 provider '{}' needs the key's PIN but there is no terminal to ask on. \
                         Set `pin = {{ secret = \"NAME\" }}` on the provider to read it from another provider.",
                        self.provider_name
                    )));
                }
                Some(Verification::TouchOnly) => {
                    eprintln!("Touch your FIDO2 key...");
                    self.assert_hmac_secret(&device, None)?
                }
                None => {
                    let pin = if is_tty {
                        let input = read_pin("FIDO2 PIN (leave empty if not required)")?;
                        if input.is_empty() { None } else { Some(input) }
                    } else {
                        None
                    };
                    eprintln!("Touch your FIDO2 key...");
                    self.assert_hmac_secret(&device, pin.as_deref())?
                }
            }
        };

        guard.insert(self.provider_name.clone(), hmac_secret.clone());

        Ok(hmac_secret)
    }

    fn assert_hmac_secret(
        &self,
        device: &ctap_hid_fido2::FidoKeyHid,
        pin: Option<&str>,
    ) -> Result<Vec<u8>> {
        let challenge = ctap_hid_fido2::verifier::create_challenge();

        let mut salt32 = [0u8; 32];
        salt32.copy_from_slice(&self.salt);

        let ext = ctap_hid_fido2::fidokey::AssertionExtension::HmacSecret(Some(salt32));

        let mut builder =
            ctap_hid_fido2::fidokey::GetAssertionArgsBuilder::new(&self.rp_id, &challenge)
                .credential_id(&self.credential_id)
                .extensions(&[ext]);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        let args = builder.build();

        let assertions = device
            .get_assertion_with_args(&args)
            .map_err(|e| FnoxError::Provider(format!("FIDO2 assertion failed: {:?}", e)))?;

        let assertion = assertions
            .first()
            .ok_or_else(|| FnoxError::Provider("FIDO2: no assertion returned".to_string()))?;

        assertion
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
            })
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

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        if secrets.is_empty() {
            return HashMap::new();
        }

        let provider = self.clone();
        let secret = match tokio::task::spawn_blocking(move || provider.get_hmac_secret()).await {
            Ok(Ok(secret)) => secret,
            Ok(Err(error)) => {
                let message = match error {
                    FnoxError::Provider(message) => message,
                    error => error.to_string(),
                };
                return batch_errors(secrets, &message);
            }
            Err(error) => {
                let message = format!("FIDO2 task failed: {error}");
                return batch_errors(secrets, &message);
            }
        };

        decrypt_batch(secrets, &secret, &self.hkdf_context())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_batch_with_shared_secret() {
        let secret = [7; 32];
        let context = b"fnox-fido2-test";
        let secrets = vec![
            (
                "FIRST".to_string(),
                hw_encrypt::encrypt(&secret, context, "one").unwrap(),
            ),
            (
                "SECOND".to_string(),
                hw_encrypt::encrypt(&secret, context, "two").unwrap(),
            ),
        ];

        let mut results = decrypt_batch(&secrets, &secret, context);

        assert_eq!(results.remove("FIRST").unwrap().unwrap(), "one");
        assert_eq!(results.remove("SECOND").unwrap().unwrap(), "two");
    }

    fn options(pairs: &[(&str, bool)]) -> Vec<(String, bool)> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn fingerprint_key_uses_biometric_even_with_pin_set() {
        let opts = options(&[("clientPin", true), ("uv", true)]);
        assert_eq!(verification_for(&opts), Verification::Biometric);
    }

    #[test]
    fn pin_only_key_asks_for_pin() {
        let opts = options(&[("clientPin", true), ("uv", false)]);
        assert_eq!(verification_for(&opts), Verification::Pin);
    }

    #[test]
    fn key_without_pin_or_uv_needs_touch_only() {
        assert_eq!(verification_for(&options(&[])), Verification::TouchOnly);
        let opts = options(&[("clientPin", false)]);
        assert_eq!(verification_for(&opts), Verification::TouchOnly);
    }

    #[test]
    fn returns_batch_error_for_each_secret() {
        let secrets = vec![
            ("FIRST".to_string(), "value-1".to_string()),
            ("SECOND".to_string(), "value-2".to_string()),
        ];

        let results = batch_errors(&secrets, "device error");

        assert_eq!(results.len(), 2);
        for result in results.values() {
            assert_eq!(
                result.as_ref().unwrap_err().to_string(),
                "Provider error: device error"
            );
        }
    }
}

/// Setup helpers for `fnox provider add <name> fido2`
pub mod setup {
    use crate::error::{FnoxError, Result};

    /// Returns (credential_id_hex, salt_hex, rp_id, pin_or_none)
    pub fn setup_fido2(provider_name: &str) -> Result<(String, String, String, Option<String>)> {
        let rp_id = format!("fnox.{}", provider_name);

        eprintln!("\nTouch your FIDO2 key when prompted...");

        let device = ctap_hid_fido2::FidoKeyHidFactory::create(
            &ctap_hid_fido2::Cfg::init().with_keep_alive_msg_to_stderr(true),
        )
        .map_err(|e| FnoxError::Provider(format!("Failed to find FIDO2 device: {:?}", e)))?;

        // Ask for a PIN only if the key has one; a fingerprint-only or
        // PIN-less key needs no prompt.
        let verification = device
            .get_info()
            .ok()
            .map(|info| super::verification_for(&info.options));
        let pin_input = match verification {
            Some(super::Verification::Biometric) => {
                eprintln!("This key verifies with its fingerprint sensor; no PIN is needed.");
                String::new()
            }
            Some(super::Verification::TouchOnly) => String::new(),
            Some(super::Verification::Pin) => {
                super::read_pin("FIDO2 PIN").map_err(|e| FnoxError::Config(e.to_string()))?
            }
            None => super::read_pin("FIDO2 PIN (leave empty if not set)")
                .map_err(|e| FnoxError::Config(e.to_string()))?,
        };
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
