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
use std::sync::{Arc, LazyLock, Mutex};

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

// Only one password prompt at a time, so prompts for different vaults don't
// share the terminal's input.
static PROMPT_LOCK: Mutex<()> = Mutex::new(());

// Serializes opens of the same vault so a command that resolves several secrets
// in parallel shows a single password prompt. Other vaults are not held up.
static OPEN_LOCKS: LazyLock<Mutex<HashMap<CacheKey, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Provider that reads secrets from an Enpass vault directory.
#[derive(Clone)]
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

/// A live Enpass item, as stored.
struct Item {
    uuid: String,
    title: String,
    folded_title: String,
    key: Vec<u8>,
}

/// One field of an Enpass item, as stored.
#[derive(Clone)]
struct Field {
    uuid: String,
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
    /// The flag is true when it was just typed, so the caller can cache it once
    /// the vault actually unlocks.
    fn get_password(&self) -> Result<(String, bool)> {
        if let Some(password) = enpass_password() {
            return Ok((password, false));
        }
        if let Some(password) = &self.password {
            return Ok((password.clone(), false));
        }
        if let Some(password) = PROMPTED_PASSWORDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&self.cache_key())
        {
            return Ok((password.clone(), false));
        }
        if !env::is_non_interactive() {
            let _prompt = PROMPT_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            return Ok((password, true));
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
            // Probing the wrong compatibility mode makes SQLCipher log to stderr.
            // SQLCipher resets its log level to WARN when it first activates on
            // `key`, so silence it after that.
            let ok = conn
                .pragma_update(None, "key", format!("x'{hex_key}'"))
                .and_then(|_| conn.pragma_update(None, "cipher_log_level", "NONE"))
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

    /// Open the live vault with the master password. Opens of one vault are
    /// serialized so concurrent lookups prompt once, and a typed password is
    /// cached only after it has unlocked the vault. If a cached password no
    /// longer works (it was changed in Enpass), drop it and prompt again.
    fn open(&self) -> Result<Connection> {
        let lock = OPEN_LOCKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(self.cache_key())
            .or_default()
            .clone();
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut retried = false;
        loop {
            let cached = self.cached_password();
            let (password, prompted) = self.get_password()?;
            let hex_key = self.derive_hex_key(&password)?;
            if let Some(conn) = self.open_with_key(&hex_key)? {
                if prompted {
                    PROMPTED_PASSWORDS
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(self.cache_key(), password);
                }
                return Ok(conn);
            }
            // A wrong password must not stay cached for the rest of the process.
            let was_cached = cached.as_deref() == Some(password.as_str());
            if was_cached {
                PROMPTED_PASSWORDS
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&self.cache_key());
            }
            if was_cached && !retried && !env::is_non_interactive() {
                retried = true;
                continue;
            }
            return Err(Self::auth_error(
                "Could not unlock the vault",
                "Check the master password (and keyfile, if the vault uses one)",
            ));
        }
    }

    /// The password typed earlier in this process for this vault, if any.
    fn cached_password(&self) -> Option<String> {
        PROMPTED_PASSWORDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&self.cache_key())
            .cloned()
    }

    /// Every live (not deleted, not trashed) item, read once per unlock. This
    /// also opens a read transaction, which the caller ends with `COMMIT` once its
    /// field reads are done, so a batch sees one consistent vault state even if
    /// Enpass writes to it meanwhile.
    fn load_items(conn: &Connection) -> Result<Vec<Item>> {
        conn.execute_batch("BEGIN")
            .map_err(|e| Self::invalid(format!("Could not read the vault: {e}"), ""))?;
        let read_err =
            |e: rusqlite::Error| Self::invalid(format!("Could not read the vault: {e}"), "");
        let mut stmt = conn
            .prepare("SELECT uuid, title, key FROM item WHERE deleted = 0 AND trashed = 0")
            .map_err(|e| Self::invalid(format!("Unexpected vault schema: {e}"), ""))?;
        stmt.query_map([], |r| {
            let title = r.get::<_, Option<String>>(1)?.unwrap_or_default();
            Ok(Item {
                uuid: r.get(0)?,
                folded_title: title.to_lowercase(),
                title,
                key: r.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
            })
        })
        .map_err(read_err)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(read_err)
    }

    /// The item with this title and its fields, or None if there is no such
    /// item. Titles match case-insensitively; this is done here rather than with
    /// SQLite's `lower()`, which only folds ASCII.
    fn fields_for(
        conn: &Connection,
        items: &[Item],
        title: &str,
    ) -> Result<Option<(String, Vec<Field>)>> {
        let read_err =
            |e: rusqlite::Error| Self::invalid(format!("Could not read the vault: {e}"), "");
        let wanted = title.to_lowercase();
        let mut matches = items.iter().filter(|i| i.folded_title == wanted);
        let Some(item) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(Self::invalid(
                format!("More than one item is titled {title:?}"),
                "Rename one of them in Enpass so the title is unique",
            ));
        }
        let (uuid, item_title, item_key) = (&item.uuid, &item.title, &item.key);
        let mut stmt = conn
            .prepare(
                "SELECT label, type, value FROM itemfield
                 WHERE item_uuid = ?1 AND deleted = 0 ORDER BY orde",
            )
            .map_err(|e| Self::invalid(format!("Unexpected vault schema: {e}"), ""))?;
        let fields = stmt
            .query_map([uuid], |r| {
                Ok(Field {
                    uuid: uuid.clone(),
                    label: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    field_type: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    value: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    item_key: item_key.clone(),
                })
            })
            .map_err(read_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(read_err)?;
        Ok(Some((item_title.clone(), fields)))
    }

    /// Parse "title" or "title/field". The field matches a field label or a
    /// field type (case-insensitive); without one, the item's password.
    fn parse_reference(value: &str) -> (&str, Option<&str>) {
        match value.rsplit_once('/') {
            Some((title, field)) if !title.is_empty() && !field.is_empty() => (title, Some(field)),
            _ => (value, None),
        }
    }

    fn find_field(conn: &Connection, items: &[Item], value: &str) -> Result<Field> {
        // Try the whole reference as a title first, so titles containing "/" work.
        let (field, found_item) = match Self::fields_for(conn, items, value)? {
            Some(item) => (None, Some(item)),
            None => {
                let (title, field) = Self::parse_reference(value);
                (field, Self::fields_for(conn, items, title)?)
            }
        };
        let Some((item_title, fields)) = found_item else {
            return Err(FnoxError::ProviderSecretNotFound {
                provider: PROVIDER.to_string(),
                secret: value.to_string(),
                hint:
                    "No item with that title in the vault (deleted and trashed items are skipped)"
                        .to_string(),
                url: DOCS_URL.to_string(),
            });
        };
        let found = match field {
            Some(name) => fields
                .iter()
                .find(|f| f.label.to_lowercase() == name.to_lowercase())
                .or_else(|| {
                    fields
                        .iter()
                        .find(|f| f.field_type.to_lowercase() == name.to_lowercase())
                }),
            None => fields.iter().find(|f| f.field_type == "password"),
        };
        let found = found.ok_or_else(|| {
            // Built-in fields are stored without a label, so name those by type.
            let mut names: Vec<&str> = fields
                .iter()
                .map(|f| {
                    if f.label.is_empty() {
                        f.field_type.as_str()
                    } else {
                        f.label.as_str()
                    }
                })
                .filter(|n| !n.is_empty() && *n != "section")
                .collect();
            names.dedup();
            Self::invalid(
                format!(
                    "Item {:?} has no {} field",
                    item_title,
                    field.unwrap_or("password")
                ),
                format!("Its fields: {}", names.join(", ")),
            )
        })?;
        Ok(found.clone())
    }
}

impl EnpassProvider {
    /// Key derivation and SQLCipher are slow, synchronous work; keep them off the runtime.
    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&EnpassProvider) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let provider = self.clone();
        tokio::task::spawn_blocking(move || f(&provider))
            .await
            .map_err(|e| FnoxError::Provider(format!("Enpass task failed: {e}")))?
    }

    /// Resolve references against one snapshot of the vault. The read
    /// transaction covers only the reads and ends before decryption, so it never
    /// holds up Enpass saving for longer than the queries take.
    fn lookup_many(conn: &Connection, values: &[&str]) -> Vec<Result<String>> {
        let found: Vec<Result<Field>> = match Self::load_items(conn) {
            Ok(items) => values
                .iter()
                .map(|value| Self::find_field(conn, &items, value))
                .collect(),
            Err(e) => values.iter().map(|_| Err(replicate_error(&e))).collect(),
        };
        let _ = conn.execute_batch("COMMIT");
        found
            .into_iter()
            .map(|field| field.and_then(|f| decrypt_field(&f)))
            .collect()
    }

    /// One unlock for the whole batch.
    fn lookup_all(&self, secrets: &[(String, String)]) -> HashMap<String, Result<String>> {
        match self.open() {
            Ok(conn) => {
                let values: Vec<&str> = secrets.iter().map(|(_, v)| v.as_str()).collect();
                secrets
                    .iter()
                    .map(|(key, _)| key.clone())
                    .zip(Self::lookup_many(&conn, &values))
                    .collect()
            }
            Err(e) => secrets
                .iter()
                .map(|(key, _)| (key.clone(), Err(replicate_error(&e))))
                .collect(),
        }
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
        let value = value.to_string();
        self.blocking(move |p| {
            let conn = p.open()?;
            Self::lookup_many(&conn, &[value.as_str()])
                .pop()
                .expect("one result per reference")
        })
        .await
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let owned = secrets.to_vec();
        match self.blocking(move |p| Ok(p.lookup_all(&owned))).await {
            Ok(results) => results,
            Err(e) => secrets
                .iter()
                .map(|(key, _)| (key.clone(), Err(replicate_error(&e))))
                .collect(),
        }
    }

    async fn test_connection(&self) -> Result<()> {
        self.blocking(|p| p.open().map(|_| ())).await
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
    env::var("FNOX_ENPASS_PASSWORD")
        .or_else(|_| env::var("ENPASS_PASSWORD"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;

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

    #[test]
    fn pbkdf2_matches_multi_iteration_vector() {
        let out = pbkdf2_sha512(b"password", b"salt", 4096);
        assert_eq!(hex::encode(&out[..16]), "d197b1b33db0143e018b12f3d1d1479e");
    }

    #[test]
    fn keyfile_accepts_xml_and_bare_hex() {
        let dir = tempfile::tempdir().unwrap();
        let xml = dir.path().join("vault.enpasskey");
        std::fs::write(
            &xml,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Key>\n  0a0b0c\n</Key>\n",
        )
        .unwrap();
        assert_eq!(read_keyfile(&xml).unwrap(), vec![0x0a, 0x0b, 0x0c]);
        let bare = dir.path().join("bare.key");
        std::fs::write(&bare, "ff00\n").unwrap();
        assert_eq!(read_keyfile(&bare).unwrap(), vec![0xff, 0x00]);
    }

    const PASSWORD: &str = "correct horse battery staple";

    type TestField<'a> = (&'a str, &'a str, &'a str);

    fn build_vault(dir: &Path, password: &str, keyfile: Option<&[u8]>, compat: u8) {
        let iterations = 2;
        std::fs::write(
            dir.join(INFO_FILE),
            serde_json::to_string_pretty(&serde_json::json!({
                "kdf_algo": "pbkdf2",
                "kdf_iter": iterations,
                "encryption_algo": "aes-256-cbc",
                "version": 6,
            }))
            .unwrap()
                + "\n",
        )
        .unwrap();
        let salt = [0x5a; SALT_LEN];
        let mut master = password.as_bytes().to_vec();
        master.extend(keyfile.unwrap_or_default());
        let key = pbkdf2_sha512(&master, &salt, iterations);
        let conn = Connection::open(dir.join(DB_FILE)).unwrap();
        // Raw key + salt makes SQLCipher write the salt as the file header.
        conn.pragma_update(
            None,
            "key",
            format!("x'{}{}'", hex::encode(&key[..32]), hex::encode(salt)),
        )
        .unwrap();
        conn.pragma_update(None, "cipher_compatibility", compat)
            .unwrap();
        conn.execute_batch(
            "CREATE TABLE item (uuid TEXT PRIMARY KEY, title TEXT, key BLOB,
                                deleted INTEGER DEFAULT 0, trashed INTEGER DEFAULT 0);
             CREATE TABLE itemfield (item_uuid TEXT, label TEXT, type TEXT, value TEXT,
                                     deleted INTEGER DEFAULT 0, orde INTEGER);",
        )
        .unwrap();

        let github: &[TestField] = &[
            ("Username", "username", "octocat"),
            ("Password", "password", "hunter2"),
            ("API Token", "password", "ghp_example"),
            ("Old password", "password", "stale"),
        ];
        add_item(
            &conn,
            "11111111-2222-4333-8444-555555555555",
            "GitHub",
            github,
            false,
        );
        conn.execute(
            "UPDATE itemfield SET deleted = 1 WHERE label = 'Old password'",
            [],
        )
        .unwrap();
        add_item(
            &conn,
            "21111111-2222-4333-8444-555555555555",
            "Prod/DB",
            &[("Password", "password", "slash-title")],
            false,
        );
        add_item(
            &conn,
            "61111111-2222-4333-8444-555555555555",
            "Labels",
            &[
                ("", "password", "built-in"),
                ("Password", "text", "labelled"),
            ],
            false,
        );
        for uuid in [
            "31111111-2222-4333-8444-555555555555",
            "41111111-2222-4333-8444-555555555555",
        ] {
            add_item(&conn, uuid, "Twin", &[("Password", "password", "x")], false);
        }
        add_item(
            &conn,
            "00000000-0000-0000-0000-0000000000a1",
            "Équipe",
            &[("Password", "password", "unicode")],
            false,
        );
        // Two items share a title, but one has no fields at all.
        add_item(
            &conn,
            "00000000-0000-0000-0000-0000000000b1",
            "Hollow Twin",
            &[("Password", "password", "x")],
            false,
        );
        add_item(
            &conn,
            "00000000-0000-0000-0000-0000000000b2",
            "Hollow Twin",
            &[],
            false,
        );
        add_item(
            &conn,
            "51111111-2222-4333-8444-555555555555",
            "Binned",
            &[("Password", "password", "gone")],
            true,
        );
    }

    fn add_item(conn: &Connection, uuid: &str, title: &str, fields: &[TestField], trashed: bool) {
        let item_key: Vec<u8> = (0u8..44)
            .map(|b| b.wrapping_mul(7) ^ uuid.as_bytes()[0])
            .collect();
        conn.execute(
            "INSERT INTO item (uuid, title, key, trashed) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![uuid, title, item_key, trashed as i64],
        )
        .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&item_key[..32]).unwrap();
        let nonce: [u8; 12] = item_key[32..44].try_into().unwrap();
        let aad = hex::decode(uuid.replace('-', "")).unwrap();
        for (order, (label, field_type, value)) in fields.iter().enumerate() {
            let stored = if *field_type == "password" {
                let sealed = cipher
                    .encrypt(
                        &Nonce::from(nonce),
                        Payload {
                            msg: value.as_bytes(),
                            aad: &aad,
                        },
                    )
                    .unwrap();
                hex::encode(sealed)
            } else {
                value.to_string()
            };
            conn.execute(
                "INSERT INTO itemfield (item_uuid, label, type, value, orde)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![uuid, label, field_type, stored, order as i64],
            )
            .unwrap();
        }
    }

    fn provider(dir: &Path, password: &str, keyfile: Option<&Path>) -> EnpassProvider {
        EnpassProvider::new(
            dir.display().to_string(),
            keyfile.map(|k| k.display().to_string()),
            Some(password.to_string()),
        )
        .unwrap()
    }

    fn env_password_set() -> bool {
        if enpass_password().is_some() {
            eprintln!("skipping: FNOX_ENPASS_PASSWORD or ENPASS_PASSWORD is set");
            return true;
        }
        false
    }

    fn test_vault(compat: u8) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        build_vault(dir.path(), PASSWORD, None, compat);
        dir
    }

    #[tokio::test]
    async fn reads_fields_from_a_vault() {
        if env_password_set() {
            return;
        }
        let dir = test_vault(4);
        let p = provider(dir.path(), PASSWORD, None);
        p.test_connection().await.unwrap();

        assert_eq!(p.get_secret("GitHub").await.unwrap(), "hunter2");
        assert_eq!(p.get_secret("GitHub/username").await.unwrap(), "octocat");
        assert_eq!(
            p.get_secret("github/api token").await.unwrap(),
            "ghp_example"
        );
        assert_eq!(p.get_secret("Labels").await.unwrap(), "built-in");
        assert_eq!(p.get_secret("Labels/password").await.unwrap(), "labelled");
        assert_eq!(p.get_secret("Prod/DB").await.unwrap(), "slash-title");
        assert_eq!(
            p.get_secret("Prod/DB/password").await.unwrap(),
            "slash-title"
        );
    }

    #[tokio::test]
    async fn matches_non_ascii_titles_and_labels_case_insensitively() {
        if env_password_set() {
            return;
        }
        let dir = test_vault(4);
        let p = provider(dir.path(), PASSWORD, None);
        assert_eq!(p.get_secret("équipe").await.unwrap(), "unicode");
        assert_eq!(p.get_secret("ÉQUIPE/password").await.unwrap(), "unicode");
    }

    #[tokio::test]
    async fn opens_sqlcipher3_vaults() {
        if env_password_set() {
            return;
        }
        let dir = test_vault(3);
        let p = provider(dir.path(), PASSWORD, None);
        assert_eq!(p.get_secret("GitHub").await.unwrap(), "hunter2");
    }

    #[tokio::test]
    async fn reports_missing_ambiguous_and_trashed_items() {
        if env_password_set() {
            return;
        }
        let dir = test_vault(4);
        let p = provider(dir.path(), PASSWORD, None);

        assert!(matches!(
            p.get_secret("Nope").await,
            Err(FnoxError::ProviderSecretNotFound { .. })
        ));
        assert!(matches!(
            p.get_secret("Binned").await,
            Err(FnoxError::ProviderSecretNotFound { .. })
        ));
        let err = p.get_secret("Twin").await.unwrap_err().to_string();
        assert!(err.contains("More than one item"), "{err}");
        let err = p.get_secret("Hollow Twin").await.unwrap_err().to_string();
        assert!(err.contains("More than one item"), "{err}");
        let err = p
            .get_secret("GitHub/Old password")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("has no Old password field"), "{err}");
    }

    #[tokio::test]
    async fn wrong_password_is_an_auth_failure_for_single_and_batch() {
        if env_password_set() {
            return;
        }
        let p = provider(&enpass_fixture(), "wrong", None);

        assert!(matches!(
            p.get_secret("password").await,
            Err(FnoxError::ProviderAuthFailed { .. })
        ));
        let batch = p
            .get_secrets_batch(&[
                ("A".to_string(), "password".to_string()),
                ("B".to_string(), "sensitive text".to_string()),
            ])
            .await;
        assert_eq!(batch.len(), 2);
        for result in batch.values() {
            assert!(
                matches!(result, Err(FnoxError::ProviderAuthFailed { .. })),
                "{result:?}"
            );
        }
    }

    #[tokio::test]
    async fn batch_resolves_each_reference() {
        if env_password_set() {
            return;
        }
        let dir = test_vault(4);
        let p = provider(dir.path(), PASSWORD, None);
        let batch = p
            .get_secrets_batch(&[
                ("USER".to_string(), "GitHub/username".to_string()),
                ("PASS".to_string(), "GitHub".to_string()),
                ("MISSING".to_string(), "Nope".to_string()),
            ])
            .await;
        assert_eq!(batch["USER"].as_ref().unwrap(), "octocat");
        assert_eq!(batch["PASS"].as_ref().unwrap(), "hunter2");
        assert!(matches!(
            batch["MISSING"],
            Err(FnoxError::ProviderSecretNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn keyfile_is_part_of_the_master_key() {
        if env_password_set() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let key_bytes = [0xab_u8; 32];
        build_vault(dir.path(), PASSWORD, Some(&key_bytes), 4);
        let keyfile = dir.path().join("vault.enpasskey");
        std::fs::write(&keyfile, format!("<Key>{}</Key>", hex::encode(key_bytes))).unwrap();

        let with_key = provider(dir.path(), PASSWORD, Some(&keyfile));
        assert_eq!(with_key.get_secret("GitHub").await.unwrap(), "hunter2");
        let without_key = provider(dir.path(), PASSWORD, None);
        assert!(matches!(
            without_key.get_secret("GitHub").await,
            Err(FnoxError::ProviderAuthFailed { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_vault_formats() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(INFO_FILE),
            r#"{"kdf_algo":"argon2","kdf_iter":3,"encryption_algo":"aes-256-cbc"}"#,
        )
        .unwrap();
        let p = provider(dir.path(), PASSWORD, None);
        let err = p.vault_info().err().unwrap().to_string();
        assert!(err.contains("Unsupported vault format"), "{err}");
    }

    fn enpass_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/enpass")
    }

    #[tokio::test]
    async fn reads_a_vault_created_by_enpass() {
        if env_password_set() {
            return;
        }
        let p = provider(&enpass_fixture(), "password", None);
        let batch = p
            .get_secrets_batch(&[
                ("DEFAULT".to_string(), "password".to_string()),
                ("BY_TYPE".to_string(), "Password/PASSWORD".to_string()),
                (
                    "SENSITIVE".to_string(),
                    "sensitive text/sensitive field".to_string(),
                ),
            ])
            .await;
        assert_eq!(batch["DEFAULT"].as_ref().unwrap(), "password");
        assert_eq!(batch["BY_TYPE"].as_ref().unwrap(), "password");
        assert_eq!(batch["SENSITIVE"].as_ref().unwrap(), "sensitive");
    }
}
