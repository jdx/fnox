use crate::env;
use crate::error::{FnoxError, Result};
use age::secrecy::{ExposeSecret, SecretString};
use async_trait::async_trait;
use std::io::Read;
use std::path::PathBuf;
use std::sync::OnceLock;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

/// Age encryption provider with cryptographically enforced 2FA.
///
/// The age private key is stored encrypted with a passphrase derived from
/// the 2FA method (TOTP shared secret or YubiKey HMAC-SHA1 response).
/// Decryption is impossible without the second factor.
pub struct Age2faProvider {
    recipients: Vec<String>,
    auth_method: AuthMethod,
    provider_name: String,
}

/// 2FA authentication method for the age-2fa provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, strum::Display)]
#[strum(serialize_all = "kebab-case")]
pub enum AuthMethod {
    /// Time-based one-time password (RFC 6238)
    Totp,
    /// YubiKey HMAC-SHA1 challenge-response
    Yubikey,
}

impl AuthMethod {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "totp" => Ok(Self::Totp),
            "yubikey" => Ok(Self::Yubikey),
            other => Err(FnoxError::Config(format!(
                "Unknown age-2fa auth method '{}'. Expected 'totp' or 'yubikey'.",
                other
            ))),
        }
    }
}

/// Cached decrypted identity for the current process.
/// After a successful 2FA, the identity is cached so subsequent decryptions
/// in the same process don't prompt again.
static CACHED_IDENTITY: OnceLock<String> = OnceLock::new();

impl Age2faProvider {
    pub fn new(recipients: Vec<String>, auth: String) -> Self {
        let provider_name = "age-2fa".to_string();
        Self {
            recipients,
            auth_method: AuthMethod::from_str(&auth).unwrap_or(AuthMethod::Totp),
            provider_name,
        }
    }

    fn twofa_dir(&self) -> PathBuf {
        env::FNOX_CONFIG_DIR.join("2fa")
    }

    fn identity_path(&self) -> PathBuf {
        self.twofa_dir().join(format!("{}.age", self.provider_name))
    }

    fn totp_config_path(&self) -> PathBuf {
        self.twofa_dir()
            .join(format!("{}.toml", self.provider_name))
    }

    /// Derive a passphrase from the TOTP shared secret using HKDF
    fn derive_passphrase_from_totp_secret(totp_secret: &[u8], salt: &[u8]) -> Result<String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(salt), totp_secret);
        let mut okm = [0u8; 32];
        hk.expand(b"fnox-age-2fa", &mut okm)
            .map_err(|e| FnoxError::Provider(format!("HKDF expansion failed: {}", e)))?;
        Ok(hex::encode(okm))
    }

    /// Get the decrypted age identity content, prompting for 2FA if needed
    fn get_identity_content(&self) -> Result<String> {
        if let Some(cached) = CACHED_IDENTITY.get() {
            return Ok(cached.clone());
        }

        let passphrase = match self.auth_method {
            AuthMethod::Totp => self.get_totp_passphrase()?,
            AuthMethod::Yubikey => self.get_yubikey_passphrase()?,
        };

        let identity_path = self.identity_path();
        let encrypted_identity =
            std::fs::read(&identity_path).map_err(|_| FnoxError::AgeIdentityNotFound {
                path: identity_path.clone(),
            })?;

        let decryptor = age::Decryptor::new(encrypted_identity.as_slice()).map_err(|e| {
            FnoxError::AgeDecryptionFailed {
                details: format!("Failed to parse encrypted identity: {}", e),
            }
        })?;

        let passphrase_secret: SecretString = passphrase.into();
        let mut reader = decryptor
            .decrypt(std::iter::once(
                &age::scrypt::Identity::new(passphrase_secret) as &dyn age::Identity,
            ))
            .map_err(|e| FnoxError::AgeDecryptionFailed {
                details: format!("Failed to decrypt age identity (wrong 2FA code?): {}", e),
            })?;

        let mut decrypted = Vec::new();
        reader
            .read_to_end(&mut decrypted)
            .map_err(|e| FnoxError::AgeDecryptionFailed {
                details: format!("Failed to read decrypted identity: {}", e),
            })?;

        let identity_content =
            String::from_utf8(decrypted).map_err(|e| FnoxError::AgeDecryptionFailed {
                details: format!("Decrypted identity is not valid UTF-8: {}", e),
            })?;

        let _ = CACHED_IDENTITY.set(identity_content.clone());
        Ok(identity_content)
    }

    fn get_totp_passphrase(&self) -> Result<String> {
        let config_path = self.totp_config_path();
        let config_content = std::fs::read_to_string(&config_path).map_err(|_| {
            FnoxError::Config(format!(
                "TOTP not configured for provider '{}'. Run 'fnox provider add --type age-2fa' first.",
                self.provider_name
            ))
        })?;

        #[derive(serde::Deserialize)]
        struct TotpConfig {
            totp_secret: String,
            salt: String,
        }

        let totp_config: TotpConfig = toml_edit::de::from_str(&config_content)
            .map_err(|e| FnoxError::Config(format!("Failed to parse TOTP config: {}", e)))?;

        let secret_bytes = data_encoding::BASE32
            .decode(totp_config.totp_secret.as_bytes())
            .map_err(|e| FnoxError::Config(format!("Invalid TOTP secret encoding: {}", e)))?;

        let code = demand::Input::new("TOTP code")
            .placeholder("6-digit code")
            .run()
            .map_err(|e| FnoxError::Config(format!("Failed to read TOTP code: {}", e)))?;

        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.clone(),
            Some("fnox".to_string()),
            self.provider_name.clone(),
        )
        .map_err(|e| FnoxError::Config(format!("Failed to create TOTP validator: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if !totp.check(&code, now) {
            return Err(FnoxError::Provider(
                "Invalid TOTP code. Please try again.".to_string(),
            ));
        }

        let salt_bytes = hex::decode(&totp_config.salt)
            .map_err(|e| FnoxError::Config(format!("Invalid salt encoding: {}", e)))?;
        Self::derive_passphrase_from_totp_secret(&secret_bytes, &salt_bytes)
    }

    fn get_yubikey_passphrase(&self) -> Result<String> {
        eprintln!("Tap your YubiKey...");

        let config_path = self.totp_config_path();
        let config_content = std::fs::read_to_string(&config_path).map_err(|_| {
            FnoxError::Config(format!(
                "YubiKey not configured for provider '{}'. Run 'fnox provider add --type age-2fa' first.",
                self.provider_name
            ))
        })?;

        #[derive(serde::Deserialize)]
        struct YubikeyConfig {
            challenge: String,
            #[serde(default = "default_slot")]
            slot: u8,
        }

        fn default_slot() -> u8 {
            2
        }

        let yk_config: YubikeyConfig = toml_edit::de::from_str(&config_content)
            .map_err(|e| FnoxError::Config(format!("Failed to parse YubiKey config: {}", e)))?;

        let challenge_bytes = hex::decode(&yk_config.challenge)
            .map_err(|e| FnoxError::Config(format!("Invalid challenge encoding: {}", e)))?;

        let mut yk = yubico_manager::Yubico::new();
        let device = yk
            .find_yubikey()
            .map_err(|e| FnoxError::Provider(format!("Failed to find YubiKey: {:?}", e)))?;

        let slot = match yk_config.slot {
            1 => yubico_manager::config::Slot::Slot1,
            _ => yubico_manager::config::Slot::Slot2,
        };

        let command = match yk_config.slot {
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
            .challenge_response_hmac(&challenge_bytes, yk_conf)
            .map_err(|e| {
                FnoxError::Provider(format!("YubiKey HMAC-SHA1 challenge failed: {:?}", e))
            })?;

        Ok(hex::encode(&*hmac_result))
    }
}

#[async_trait]
impl crate::providers::Provider for Age2faProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String> {
        use std::io::Write;

        if self.recipients.is_empty() {
            return Err(FnoxError::AgeNotConfigured);
        }

        // Encryption uses the public key only — no 2FA needed
        let mut parsed_recipients: Vec<Box<dyn age::Recipient + Send + Sync>> = Vec::new();

        for recipient in &self.recipients {
            if let Ok(ssh_recipient) = recipient.parse::<age::ssh::Recipient>() {
                parsed_recipients.push(Box::new(ssh_recipient));
                continue;
            }
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

        let encryptor = age::Encryptor::with_recipients(
            parsed_recipients
                .iter()
                .map(|r| r.as_ref() as &dyn age::Recipient),
        )
        .expect("we provided at least one recipient");

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

        use base64::Engine;
        let encrypted_base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        Ok(encrypted_base64)
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let encrypted_bytes =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value) {
                Ok(bytes) => bytes,
                Err(_) => value.as_bytes().to_vec(),
            };

        let identity_content = self.get_identity_content()?;

        let identities = {
            let cursor = std::io::Cursor::new(identity_content.as_bytes());
            age::IdentityFile::from_buffer(cursor)
                .map_err(|e| FnoxError::AgeIdentityParseFailed {
                    details: e.to_string(),
                })?
                .into_identities()
                .map_err(|e| FnoxError::AgeIdentityParseFailed {
                    details: e.to_string(),
                })?
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

/// Setup helpers for the `fnox provider add --type age-2fa` flow
pub mod setup {
    use super::*;
    use std::io::Write;

    /// Generate a new age-2fa provider, creating encrypted identity and 2FA config.
    /// Returns the recipients (public keys) to store in fnox.toml.
    pub fn setup_age_2fa(provider_name: &str, auth_method: &str) -> Result<Vec<String>> {
        let method = AuthMethod::from_str(auth_method)?;
        let twofa_dir = env::FNOX_CONFIG_DIR.join("2fa");
        std::fs::create_dir_all(&twofa_dir)
            .map_err(|e| FnoxError::Config(format!("Failed to create 2FA directory: {}", e)))?;

        // Generate a new age keypair
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let identity_str = identity.to_string();

        let passphrase = match method {
            AuthMethod::Totp => setup_totp(provider_name, &twofa_dir)?,
            AuthMethod::Yubikey => setup_yubikey(provider_name, &twofa_dir)?,
        };

        // Encrypt the age identity with the passphrase
        let encrypted_identity =
            encrypt_with_passphrase(identity_str.expose_secret(), &passphrase)?;

        let identity_path = twofa_dir.join(format!("{}.age", provider_name));
        std::fs::write(&identity_path, &encrypted_identity)
            .map_err(|e| FnoxError::Config(format!("Failed to write encrypted identity: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    FnoxError::Config(format!("Failed to set permissions on identity file: {}", e))
                })?;
        }

        Ok(vec![recipient])
    }

    fn generate_random_salt() -> [u8; 32] {
        // Use age's key generation as entropy source
        let random_identity = age::x25519::Identity::generate();
        let hash = blake3::hash(random_identity.to_string().expose_secret().as_bytes());
        *hash.as_bytes()
    }

    fn setup_totp(provider_name: &str, twofa_dir: &PathBuf) -> Result<String> {
        use totp_rs::TOTP;

        let secret = totp_rs::Secret::generate_secret();
        let secret_bytes = secret
            .to_bytes()
            .map_err(|e| FnoxError::Config(format!("Failed to generate TOTP secret: {}", e)))?;
        let secret_base32 = data_encoding::BASE32.encode(&secret_bytes);

        let salt = generate_random_salt();
        let salt_hex = hex::encode(salt);

        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.clone(),
            Some("fnox".to_string()),
            provider_name.to_string(),
        )
        .map_err(|e| FnoxError::Config(format!("Failed to create TOTP: {}", e)))?;

        let otpauth_url = format!(
            "otpauth://totp/fnox:{}?secret={}&issuer=fnox&algorithm=SHA1&digits=6&period=30",
            provider_name, secret_base32
        );

        eprintln!("\nAdd this to your authenticator app:");
        eprintln!("  Secret: {}", secret_base32);
        eprintln!("  URL: {}", otpauth_url);
        eprintln!();

        let code = demand::Input::new("Enter TOTP code to verify setup")
            .placeholder("6-digit code")
            .run()
            .map_err(|e| FnoxError::Config(format!("Failed to read TOTP code: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if !totp.check(&code, now) {
            return Err(FnoxError::Config(
                "Invalid TOTP code. Setup aborted.".to_string(),
            ));
        }

        let config_path = twofa_dir.join(format!("{}.toml", provider_name));
        let config_content = format!(
            "totp_secret = \"{}\"\nsalt = \"{}\"\n",
            secret_base32, salt_hex
        );
        std::fs::write(&config_path, &config_content)
            .map_err(|e| FnoxError::Config(format!("Failed to write TOTP config: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    FnoxError::Config(format!("Failed to set permissions on TOTP config: {}", e))
                })?;
        }

        Age2faProvider::derive_passphrase_from_totp_secret(&secret_bytes, &salt)
    }

    fn setup_yubikey(provider_name: &str, twofa_dir: &PathBuf) -> Result<String> {
        eprintln!("\nPlug in your YubiKey and tap it when prompted...");

        let challenge = generate_random_salt();
        let challenge_hex = hex::encode(challenge);

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

        eprintln!("Tap your YubiKey now...");

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

        let hmac_result = yk
            .challenge_response_hmac(&challenge, yk_conf)
            .map_err(|e| {
                FnoxError::Provider(format!("YubiKey HMAC-SHA1 challenge failed: {:?}", e))
            })?;

        let passphrase = hex::encode(&*hmac_result);

        let config_path = twofa_dir.join(format!("{}.toml", provider_name));
        let config_content = format!("challenge = \"{}\"\nslot = {}\n", challenge_hex, slot_num);
        std::fs::write(&config_path, &config_content)
            .map_err(|e| FnoxError::Config(format!("Failed to write YubiKey config: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    FnoxError::Config(format!(
                        "Failed to set permissions on YubiKey config: {}",
                        e
                    ))
                })?;
        }

        Ok(passphrase)
    }

    fn encrypt_with_passphrase(plaintext: &str, passphrase: &str) -> Result<Vec<u8>> {
        let passphrase_secret: SecretString = passphrase.to_string().into();
        let encryptor = age::Encryptor::with_user_passphrase(passphrase_secret);

        let mut encrypted = vec![];
        let mut writer =
            encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| FnoxError::AgeEncryptionFailed {
                    details: format!("Failed to create passphrase-encrypted writer: {}", e),
                })?;

        writer
            .write_all(plaintext.as_bytes())
            .map_err(|e| FnoxError::AgeEncryptionFailed {
                details: format!("Failed to write identity: {}", e),
            })?;

        writer
            .finish()
            .map_err(|e| FnoxError::AgeEncryptionFailed {
                details: format!("Failed to finalize encryption: {}", e),
            })?;

        Ok(encrypted)
    }
}
