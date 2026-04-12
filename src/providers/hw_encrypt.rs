//! Shared symmetric encryption for hardware-backed providers (YubiKey, FIDO2).
//!
//! Derives an AES-256-GCM key from a hardware-provided secret using HKDF-SHA256,
//! then encrypts/decrypts secret values. The encrypted output is:
//! `base64(nonce || ciphertext || tag)`.

use crate::error::{FnoxError, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 256-bit AES key from raw hardware secret bytes using HKDF.
fn derive_key(hw_secret: &[u8], context: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, hw_secret);
    let mut key = [0u8; 32];
    // info string scopes the derivation to fnox + the provider context
    hk.expand(context, &mut key)
        .expect("HKDF-SHA256 expand should not fail for 32 bytes");
    key
}

/// Encrypt a plaintext string using a hardware-derived secret.
/// Returns a base64-encoded blob of `nonce || ciphertext || tag`.
pub fn encrypt(hw_secret: &[u8], context: &[u8], plaintext: &str) -> Result<String> {
    let key_bytes = derive_key(hw_secret, context);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| FnoxError::Provider(format!("Failed to create AES-256-GCM cipher: {}", e)))?;

    // Generate a random 96-bit nonce using the OS CSPRNG
    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| FnoxError::Provider(format!("AES-256-GCM encryption failed: {}", e)))?;

    // Prepend nonce to ciphertext
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&output))
}

/// Decrypt a base64-encoded blob using a hardware-derived secret.
pub fn decrypt(hw_secret: &[u8], context: &[u8], encrypted: &str) -> Result<String> {
    let key_bytes = derive_key(hw_secret, context);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| FnoxError::Provider(format!("Failed to create AES-256-GCM cipher: {}", e)))?;

    use base64::Engine;
    let data = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| FnoxError::Provider(format!("Invalid base64: {}", e)))?;

    if data.len() < 12 {
        return Err(FnoxError::Provider(
            "Encrypted data too short (missing nonce)".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| FnoxError::Provider("Invalid nonce length".to_string()))?;
    let nonce = Nonce::from(nonce_arr);

    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        FnoxError::Provider("Decryption failed — wrong hardware key or corrupted data".to_string())
    })?;

    String::from_utf8(plaintext)
        .map_err(|e| FnoxError::Provider(format!("Decrypted data is not valid UTF-8: {}", e)))
}
