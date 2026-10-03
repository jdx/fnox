//! Enpass provider: reads secrets straight from a live Enpass vault (read-only).
//!
//! An Enpass 6 vault is a directory holding `vault.json` (KDF parameters) and
//! `vault.enpassdb`, an SQLCipher database. The database key is
//! PBKDF2-HMAC-SHA512 over the master password (plus the decoded keyfile, if
//! any), salted with the database file's first 16 bytes; the raw SQLCipher key
//! is the first 32 bytes of that output. Password-type fields are additionally
//! encrypted per item with AES-256-GCM: the item's `key` column holds a 32-byte
//! key and a 12-byte nonce, and the item UUID (without dashes) is the AAD.
//!
//! Every lookup reads the vault file as it is now, so changes made in Enpass
//! show up immediately; nothing is copied out of the vault.

use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OpenFlags};
use sha2::Sha512;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

const PROVIDER: &str = "Enpass";
const DOCS_URL: &str = "https://fnox.jdx.dev/providers/enpass";
const SALT_LEN: usize = 16;
const DB_FILE: &str = "vault.enpassdb";
const INFO_FILE: &str = "vault.json";

type CacheKey = (PathBuf, Option<PathBuf>);

// Provider instances are recreated for separate resolution levels. Cache only
// prompted passwords for the lifetime of this process, keyed by vault and
// keyfile, so one command asks once even across those levels.
static PROMPTED_PASSWORDS: LazyLock<Mutex<HashMap<CacheKey, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Provider that reads secrets from an Enpass vault directory.
pub struct EnpassProvider {
    vault_dir: PathBuf,
    keyfile_path: Option<PathBuf>,
    password: Option<String>,
}

#[derive(serde::Deserialize)]
struct VaultInfo {
    #[serde(default)]
    kdf_algo: String,
    #[serde(default)]
    kdf_iter: u32,
    #[serde(default)]
    encryption_algo: String,
}

/// One field of an Enpass item, as stored.
struct Field {
    uuid: String,
    title: String,
    label: String,
    field_type: String,
    value: String,
    item_key: Vec<u8>,
}

impl EnpassProvider {
    pub fn new(vault: String, keyfile: Option<String>, password: Option<String>) -> Result<Self> {
        Ok(Self {
            vault_dir: crate::config_path::resolve_relative_to_file(&vault, None),
            keyfile_path: keyfile.map(|k| crate::config_path::resolve_relative_to_file(&k, None)),
            password,
        })
    }

    fn cache_key(&self) -> CacheKey {
        (self.vault_dir.clone(), self.keyfile_path.clone())
    }

    fn auth_error(details: impl Into<String>, hint: impl Into<String>) -> FnoxError {
        FnoxError::ProviderAuthFailed {
            provider: PROVIDER.to_string(),
            details: details.into(),
            hint: hint.into(),
            url: DOCS_URL.to_string(),
        }
    }

    fn invalid(details: impl Into<String>, hint: impl Into<String>) -> FnoxError {
        FnoxError::ProviderInvalidResponse {
            provider: PROVIDER.to_string(),
            details: details.into(),
            hint: hint.into(),
            url: DOCS_URL.to_string(),
        }
    }

    /// The master password: environment, then config, then a terminal prompt.
    fn get_password(&self) -> Result<String> {
        if let Some(password) = enpass_password() {
            return Ok(password);
        }
        if let Some(password) = &self.password {
            return Ok(password.clone());
        }
        let mut prompted = PROMPTED_PASSWORDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(password) = prompted.get(&self.cache_key()) {
            return Ok(password.clone());
        }
        if !env::is_non_interactive() {
            let password = rpassword::prompt_password(format!(
                "Enpass master password for {}: ",
                self.vault_dir.display()
            ))
            .map_err(|e| {
                Self::auth_error(
                    format!("Could not read the master password from the terminal: {e}"),
                    "Set FNOX_ENPASS_PASSWORD or ENPASS_PASSWORD instead",
                )
            })?;
            prompted.insert(self.cache_key(), password.clone());
            return Ok(password);
        }
        Err(Self::auth_error(
            "Master password not set",
            "Run in a terminal to enter it, or set FNOX_ENPASS_PASSWORD or ENPASS_PASSWORD",
        ))
    }

    fn vault_info(&self) -> Result<VaultInfo> {
        let path = self.vault_dir.join(INFO_FILE);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            Self::invalid(
                format!("Could not read {}: {e}", path.display()),
                "Point `vault` at an Enpass vault directory (it holds vault.json and vault.enpassdb)",
            )
        })?;
        let info: VaultInfo = serde_json::from_str(&text)
            .map_err(|e| Self::invalid(format!("Could not parse {}: {e}", path.display()), ""))?;
        if info.kdf_algo != "pbkdf2" || info.encryption_algo != "aes-256-cbc" || info.kdf_iter == 0
        {
            return Err(Self::invalid(
                format!(
                    "Unsupported vault format (kdf {} x{}, cipher {})",
                    info.kdf_algo, info.kdf_iter, info.encryption_algo
                ),
                "Only Enpass 6 vaults (PBKDF2 + SQLCipher) are supported",
            ));
        }
        Ok(info)
    }

    /// Master password bytes, plus the decoded keyfile when one is configured.
    fn master_bytes(&self, password: &str) -> Result<Vec<u8>> {
        let mut bytes = password.as_bytes().to_vec();
        if let Some(keyfile) = &self.keyfile_path {
            bytes.extend(read_keyfile(keyfile)?);
        }
        Ok(bytes)
    }

    fn db_path(&self) -> PathBuf {
        self.vault_dir.join(DB_FILE)
    }

    /// The SQLCipher raw key (hex) for this vault and master password.
    fn derive_hex_key(&self, password: &str) -> Result<String> {
        let db_path = self.db_path();
        let mut salt = [0u8; SALT_LEN];
        std::fs::File::open(&db_path)
            .and_then(|mut f| f.read_exact(&mut salt))
            .map_err(|e| {
                Self::invalid(
                    format!("Could not read {}: {e}", db_path.display()),
                    "Check the vault path",
                )
            })?;
        let info = self.vault_info()?;
        let master = self.master_bytes(password)?;
        let key = pbkdf2_sha512(&master, &salt, info.kdf_iter);
        Ok(hex::encode(&key[..32]))
    }

    /// Open the database read-only with a raw key; None if the key is wrong.
    fn open_with_key(&self, hex_key: &str) -> Result<Option<Connection>> {
        // SQLCipher 4 for Enpass 6.8+, 3 for older vaults.
        for compat in [4, 3] {
            let conn = Connection::open_with_flags(
                self.db_path(),
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| Self::invalid(format!("Could not open the vault: {e}"), ""))?;
            let ok = conn
                .pragma_update(None, "key", format!("x'{hex_key}'"))
                .and_then(|_| conn.pragma_update(None, "cipher_compatibility", compat))
                .and_then(|_| {
                    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
                        r.get::<_, i64>(0)
                    })
                })
                .is_ok();
            if ok {
                return Ok(Some(conn));
            }
        }
        Ok(None)
    }

    /// Open the live vault with the master password.
    fn open(&self) -> Result<Connection> {
        let hex_key = self.derive_hex_key(&self.get_password()?)?;
        if let Some(conn) = self.open_with_key(&hex_key)? {
            return Ok(conn);
        }
        // A wrong password must not stay cached for the rest of the process.
        PROMPTED_PASSWORDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.cache_key());
        Err(Self::auth_error(
            "Could not unlock the vault",
            "Check the master password (and keyfile, if the vault uses one)",
        ))
    }

    /// Fields of live (not deleted, not trashed) items whose title matches.
    fn fields_for(conn: &Connection, title: &str) -> Result<Vec<Field>> {
        let mut stmt = conn
            .prepare(
                "SELECT item.uuid, item.title, itemfield.label, itemfield.type, itemfield.value, item.key
                 FROM item INNER JOIN itemfield ON item.uuid = itemfield.item_uuid
                 WHERE item.deleted = 0 AND item.trashed = 0 AND itemfield.deleted = 0
                   AND lower(item.title) = lower(?1)
                 ORDER BY item.uuid, itemfield.orde",
            )
            .map_err(|e| Self::invalid(format!("Unexpected vault schema: {e}"), ""))?;
        let rows = stmt
            .query_map([title], |r| {
                Ok(Field {
                    uuid: r.get(0)?,
                    title: r.get(1)?,
                    label: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    field_type: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    value: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    item_key: r.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default(),
                })
            })
            .map_err(|e| Self::invalid(format!("Could not read the vault: {e}"), ""))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Self::invalid(format!("Could not read the vault: {e}"), ""))
    }

    /// Parse "title" or "title/field". The field matches a field label or a
    /// field type (case-insensitive); without one, the item's password.
    fn parse_reference(value: &str) -> (&str, Option<&str>) {
        match value.rsplit_once('/') {
            Some((title, field)) if !title.is_empty() && !field.is_empty() => (title, Some(field)),
            _ => (value, None),
        }
    }

    fn lookup(conn: &Connection, value: &str) -> Result<String> {
        // Try the whole reference as a title first, so titles containing "/" work.
        let (title, field, fields) = {
            let whole = Self::fields_for(conn, value)?;
            if !whole.is_empty() {
                (value, None, whole)
            } else {
                let (title, field) = Self::parse_reference(value);
                (title, field, Self::fields_for(conn, title)?)
            }
        };
        if fields.is_empty() {
            return Err(FnoxError::ProviderSecretNotFound {
                provider: PROVIDER.to_string(),
                secret: value.to_string(),
                hint:
                    "No item with that title in the vault (deleted and trashed items are skipped)"
                        .to_string(),
                url: DOCS_URL.to_string(),
            });
        }
        let first_uuid = fields[0].uuid.clone();
        if fields.iter().any(|f| f.uuid != first_uuid) {
            return Err(Self::invalid(
                format!("More than one item is titled {title:?}"),
                "Rename one of them in Enpass so the title is unique",
            ));
        }
        let wanted = |f: &&Field| match field {
            Some(name) => {
                f.label.eq_ignore_ascii_case(name) || f.field_type.eq_ignore_ascii_case(name)
            }
            None => f.field_type == "password",
        };
        let found = fields.iter().find(wanted).ok_or_else(|| {
            let names: Vec<&str> = fields
                .iter()
                .map(|f| f.label.as_str())
                .filter(|l| !l.is_empty())
                .collect();
            Self::invalid(
                format!(
                    "Item {:?} has no {} field",
                    fields[0].title,
                    field.unwrap_or("password")
                ),
                format!("Its fields: {}", names.join(", ")),
            )
        })?;
        decrypt_field(found)
    }
}

/// Field value in plain text: password fields are AES-256-GCM encrypted per item.
fn decrypt_field(field: &Field) -> Result<String> {
    if field.value.is_empty() || field.field_type != "password" {
        return Ok(field.value.clone());
    }
    if field.item_key.len() < 44 {
        return Err(EnpassProvider::invalid(
            "Item key is missing or truncated",
            "",
        ));
    }
    let ciphertext = hex::decode(&field.value)
        .map_err(|e| EnpassProvider::invalid(format!("Field value isn't hex: {e}"), ""))?;
    let aad = hex::decode(field.uuid.replace('-', ""))
        .map_err(|e| EnpassProvider::invalid(format!("Item UUID isn't hex: {e}"), ""))?;
    let cipher = Aes256Gcm::new_from_slice(&field.item_key[..32])
        .map_err(|e| EnpassProvider::invalid(format!("Bad item key: {e}"), ""))?;
    let nonce_arr: [u8; 12] = field.item_key[32..44]
        .try_into()
        .map_err(|_| EnpassProvider::invalid("Bad item nonce", ""))?;
    let plaintext = cipher
        .decrypt(
            &Nonce::from(nonce_arr),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| EnpassProvider::invalid("Could not decrypt the field", ""))?;
    String::from_utf8(plaintext)
        .map_err(|e| EnpassProvider::invalid(format!("Field isn't UTF-8: {e}"), ""))
}

/// PBKDF2-HMAC-SHA512 producing 64 bytes (one block).
fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    type HmacSha512 = Hmac<Sha512>;
    let prf = HmacSha512::new_from_slice(password).expect("HMAC accepts any key length");
    let mut u = {
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&1u32.to_be_bytes());
        let mut block = [0u8; 64];
        block.copy_from_slice(&mac.finalize().into_bytes());
        block
    };
    let mut out = u;
    for _ in 1..iterations {
        let mut mac = prf.clone();
        mac.update(&u);
        u.copy_from_slice(&mac.finalize().into_bytes());
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// An Enpass keyfile is XML whose inner text is the key in hex.
fn read_keyfile(path: &Path) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        EnpassProvider::invalid(
            format!("Could not read keyfile {}: {e}", path.display()),
            "",
        )
    })?;
    let inner = text
        .find("<Key>")
        .and_then(|start| {
            text[start + 5..]
                .find("</Key>")
                .map(|end| &text[start + 5..start + 5 + end])
        })
        .unwrap_or(text.as_str())
        .trim();
    hex::decode(inner).map_err(|e| EnpassProvider::invalid(format!("Keyfile isn't hex: {e}"), ""))
}

#[async_trait]
impl crate::providers::Provider for EnpassProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::RemoteRead]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!(
            "Getting Enpass secret '{}' from '{}'",
            value,
            self.vault_dir.display()
        );
        let conn = self.open()?;
        Self::lookup(&conn, value)
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        // One unlock for the whole batch.
        match self.open() {
            Ok(conn) => secrets
                .iter()
                .map(|(key, value)| (key.clone(), Self::lookup(&conn, value)))
                .collect(),
            Err(e) => secrets
                .iter()
                .map(|(key, _)| (key.clone(), Err(replicate_error(&e))))
                .collect(),
        }
    }

    async fn test_connection(&self) -> Result<()> {
        self.open().map(|_| ())
    }
}

fn replicate_error(e: &FnoxError) -> FnoxError {
    match e {
        FnoxError::ProviderAuthFailed {
            details, hint, url, ..
        } => FnoxError::ProviderAuthFailed {
            provider: PROVIDER.to_string(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderInvalidResponse {
            details, hint, url, ..
        } => FnoxError::ProviderInvalidResponse {
            provider: PROVIDER.to_string(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        other => FnoxError::Provider(other.to_string()),
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &["ENPASS_PASSWORD", "FNOX_ENPASS_PASSWORD"]
}

fn enpass_password() -> Option<String> {
    std::env::var("FNOX_ENPASS_PASSWORD")
        .or_else(|_| std::env::var("ENPASS_PASSWORD"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reference_splits_last_segment() {
        assert_eq!(EnpassProvider::parse_reference("GitHub"), ("GitHub", None));
        assert_eq!(
            EnpassProvider::parse_reference("GitHub/username"),
            ("GitHub", Some("username"))
        );
        assert_eq!(EnpassProvider::parse_reference("a/b/c"), ("a/b", Some("c")));
    }

    #[test]
    fn pbkdf2_matches_rfc_vector() {
        // PBKDF2-HMAC-SHA512, P="password", S="salt", c=1 (well-known test vector)
        let out = pbkdf2_sha512(b"password", b"salt", 1);
        assert_eq!(hex::encode(&out[..16]), "867f70cf1ade02cff3752599a3a53dc4");
    }
}
