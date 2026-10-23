use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use async_trait::async_trait;
use keepass::DatabaseKey;
use keepass::db::{Database, EntryId, GroupId, GroupRef};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use tempfile::NamedTempFile;

type PasswordCacheKey = (PathBuf, Option<PathBuf>);

// Provider instances are recreated for separate resolution levels. Cache only
// prompted passwords for the lifetime of this process, keyed by the database
// and keyfile, so one command asks once even across those levels.
static PROMPTED_PASSWORDS: LazyLock<Mutex<HashMap<PasswordCacheKey, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Provider that reads and writes secrets from KeePass database files (.kdbx)
pub struct KeePassProvider {
    database_path: PathBuf,
    keyfile_path: Option<PathBuf>,
    password: Option<String>,
}

impl KeePassProvider {
    pub fn new(
        database: String,
        keyfile: Option<String>,
        password: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            database_path: crate::config_path::resolve_relative_to_file(&database, None),
            keyfile_path: keyfile.map(|k| crate::config_path::resolve_relative_to_file(&k, None)),
            password,
        })
    }

    /// Get the password from the environment, config, or a terminal prompt.
    fn get_password(&self) -> Result<String> {
        // Priority: env var > config > prompt.
        if let Some(password) = keepass_password() {
            return Ok(password);
        }

        if let Some(password) = &self.password {
            return Ok(password.clone());
        }

        // Hold the lock while prompting so concurrent resolutions of the same
        // database do not each request the password.
        let mut prompted = PROMPTED_PASSWORDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cache_key = (self.database_path.clone(), self.keyfile_path.clone());
        if let Some(password) = prompted.get(&cache_key) {
            return Ok(password.clone());
        }
        if !env::is_non_interactive() {
            let password = rpassword::prompt_password(format!(
                "KeePass password for {}: ",
                self.database_path.display()
            ))
            .map_err(|e| FnoxError::ProviderAuthFailed {
                provider: "KeePass".to_string(),
                details: format!("Could not read database password from terminal: {e}"),
                hint: "Set FNOX_KEEPASS_PASSWORD or KEEPASS_PASSWORD instead".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })?;
            prompted.insert(cache_key, password.clone());
            return Ok(password);
        }

        Err(FnoxError::ProviderAuthFailed {
            provider: "KeePass".to_string(),
            details: "Database password not set".to_string(),
            hint: "Run in a terminal to enter the password, or set FNOX_KEEPASS_PASSWORD or KEEPASS_PASSWORD".to_string(),
            url: "https://fnox.jdx.dev/providers/keepass".to_string(),
        })
    }

    /// Build the database key from password and optional keyfile
    fn build_key(&self) -> Result<DatabaseKey> {
        let password = self.get_password()?;
        let mut key = DatabaseKey::new();

        // Add password
        key = key.with_password(&password);

        // Add keyfile if configured
        if let Some(keyfile_path) = &self.keyfile_path {
            let mut keyfile =
                File::open(keyfile_path).map_err(|e| FnoxError::ProviderApiError {
                    provider: "KeePass".to_string(),
                    details: format!("Failed to open keyfile '{}': {}", keyfile_path.display(), e),
                    hint: "Check that the keyfile exists and is readable".to_string(),
                    url: "https://fnox.jdx.dev/providers/keepass".to_string(),
                })?;
            key = key
                .with_keyfile(&mut keyfile)
                .map_err(|e| FnoxError::ProviderApiError {
                    provider: "KeePass".to_string(),
                    details: format!("Failed to read keyfile: {}", e),
                    hint: "Check that the keyfile is valid".to_string(),
                    url: "https://fnox.jdx.dev/providers/keepass".to_string(),
                })?;
        }

        Ok(key)
    }

    /// Open and decrypt the database
    fn open_database(&self) -> Result<Database> {
        let file = File::open(&self.database_path).map_err(|e| FnoxError::ProviderApiError {
            provider: "KeePass".to_string(),
            details: format!(
                "Failed to open database '{}': {}",
                self.database_path.display(),
                e
            ),
            hint: "Check that the database file exists and is readable".to_string(),
            url: "https://fnox.jdx.dev/providers/keepass".to_string(),
        })?;
        let mut reader = BufReader::new(file);
        let key = self.build_key()?;

        Database::open(&mut reader, key).map_err(|e| FnoxError::ProviderAuthFailed {
            provider: "KeePass".to_string(),
            details: format!("Failed to decrypt database: {}", e),
            hint: "Check that the password and/or keyfile are correct".to_string(),
            url: "https://fnox.jdx.dev/providers/keepass".to_string(),
        })
    }

    /// Save the database back to disk
    fn save_database(&self, db: &Database) -> Result<()> {
        // Write to a temporary file first, then atomically rename to avoid data loss
        // if the save fails partway through (File::create truncates immediately)
        let parent_dir = self.database_path.parent().unwrap_or(Path::new("."));

        // Create parent directory if it doesn't exist (for new databases)
        if !parent_dir.exists() {
            std::fs::create_dir_all(parent_dir).map_err(|e| FnoxError::ProviderApiError {
                provider: "KeePass".to_string(),
                details: format!(
                    "Failed to create directory '{}': {}",
                    parent_dir.display(),
                    e
                ),
                hint: "Check directory permissions".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })?;
        }

        // Create temp file in same directory (required for atomic rename on same filesystem)
        // NamedTempFile handles unique naming to avoid race conditions
        let temp_file =
            NamedTempFile::new_in(parent_dir).map_err(|e| FnoxError::ProviderApiError {
                provider: "KeePass".to_string(),
                details: format!(
                    "Failed to create temporary file in '{}': {}",
                    parent_dir.display(),
                    e
                ),
                hint: "Check directory permissions".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })?;

        let mut writer = BufWriter::new(temp_file);
        let key = self.build_key()?;

        // Save to temp file
        db.save(&mut writer, key)
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "KeePass".to_string(),
                details: format!("Failed to save database: {}", e),
                hint: "Check that you have write permissions".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })?;

        // Flush buffer to file
        writer.flush().map_err(|e| FnoxError::ProviderApiError {
            provider: "KeePass".to_string(),
            details: format!("Failed to flush database: {}", e),
            hint: "Check disk space and permissions".to_string(),
            url: "https://fnox.jdx.dev/providers/keepass".to_string(),
        })?;

        // Sync to disk to ensure durability before rename
        writer
            .get_ref()
            .as_file()
            .sync_all()
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "KeePass".to_string(),
                details: format!("Failed to sync database to disk: {}", e),
                hint: "Check disk space and permissions".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })?;

        // Atomically rename temp file to target (preserves original on failure)
        // Note: into_inner() returns the NamedTempFile, which we then persist
        let temp_file = writer
            .into_inner()
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "KeePass".to_string(),
                details: format!("Failed to finalize temp file: {}", e),
                hint: "Check disk space and permissions".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })?;

        temp_file
            .persist(&self.database_path)
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "KeePass".to_string(),
                details: format!(
                    "Failed to persist database to '{}': {}",
                    self.database_path.display(),
                    e
                ),
                hint: "Check file permissions".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })?;

        Ok(())
    }

    /// Parse a reference value into (entry_path, field)
    /// Formats:
    /// - "entry-name" -> (["entry-name"], "Password")
    /// - "entry-name/username" -> (["entry-name"], "UserName")
    /// - "group/subgroup/entry-name" -> (["group", "subgroup", "entry-name"], "Password")
    /// - "group/subgroup/entry-name/password" -> (["group", "subgroup", "entry-name"], "Password")
    fn parse_reference(value: &str) -> (Vec<&str>, &str) {
        let parts: Vec<&str> = value.split('/').collect();

        // Known field names (case-insensitive check, but return proper casing)
        let known_fields = ["password", "username", "url", "notes", "title"];

        if parts.len() == 1 {
            // Just entry name, default to password
            (parts, "Password")
        } else {
            // Check if the last part is a known field
            let last = parts.last().unwrap().to_lowercase();
            if known_fields.contains(&last.as_str()) {
                let field = match last.as_str() {
                    "password" => "Password",
                    "username" => "UserName",
                    "url" => "URL",
                    "notes" => "Notes",
                    "title" => "Title",
                    _ => "Password",
                };
                (parts[..parts.len() - 1].to_vec(), field)
            } else {
                // Last part is not a known field, treat entire path as entry path
                (parts, "Password")
            }
        }
    }

    /// Resolve a reference to a field value in an open database.
    fn read_field(db: &Database, value: &str) -> Result<String> {
        let (mut entry_path, mut field) = Self::parse_reference(value);

        let mut entry_id = Self::find_entry_id(db, &entry_path);
        let explicit_field = entry_path.len() < value.split('/').count();
        if entry_id.is_none() && !explicit_field && entry_path.len() > 1 {
            // No entry has that title and the reference did not end in a standard
            // field name, so the last segment may name a custom field of the entry
            // before it (e.g. "group/entry/customField").
            let parent = &entry_path[..entry_path.len() - 1];
            if let Some(id) = Self::find_entry_id(db, parent) {
                field = entry_path[entry_path.len() - 1];
                entry_path = parent.to_vec();
                entry_id = Some(id);
            }
        }
        let entry_id = entry_id.ok_or_else(|| FnoxError::ProviderSecretNotFound {
            provider: "KeePass".to_string(),
            secret: entry_path.join("/"),
            hint: "Check that the entry exists in the database".to_string(),
            url: "https://fnox.jdx.dev/providers/keepass".to_string(),
        })?;
        let entry = db.entry(entry_id).expect("entry exists");

        entry
            .get(field)
            .map(|s| s.to_string())
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "KeePass".to_string(),
                details: format!(
                    "Field '{}' not found in entry '{}'",
                    field,
                    entry_path.join("/")
                ),
                hint: "Available fields: password, username, url, notes, title, or a custom field name".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })
    }

    /// Maximum depth of chained field references before giving up (guards cycles).
    const MAX_REF_DEPTH: usize = 10;

    /// Maximum number of references resolved for a single secret, bounding total
    /// work and output when references repeat (e.g. one field naming the next ten times).
    const MAX_REF_LOOKUPS: usize = 256;

    /// Resolve all field references in `value`.
    fn resolve_refs(db: &Database, value: &str) -> Result<String> {
        let mut lookups = 0;
        Self::resolve_field_refs(db, value, 0, &mut lookups)
    }

    /// Map a KeePass field-reference letter to its field name.
    /// See <https://keepass.info/help/base/fieldrefs.html>.
    fn ref_field_name(code: char) -> Option<&'static str> {
        match code.to_ascii_uppercase() {
            'T' => Some("Title"),
            'U' => Some("UserName"),
            'P' => Some("Password"),
            'A' => Some("URL"),
            'N' => Some("Notes"),
            _ => None,
        }
    }

    /// Resolve KeePass field references (`{REF:<Wanted>@<SearchIn>:<Text>}`) in a
    /// field value, following nested references up to `MAX_REF_DEPTH` levels.
    fn resolve_field_refs(
        db: &Database,
        value: &str,
        depth: usize,
        lookups: &mut usize,
    ) -> Result<String> {
        const START: &str = "{REF:";
        let mut out = String::with_capacity(value.len());
        let mut rest = value;
        while let Some(start) = rest.find(START) {
            let after = &rest[start + START.len()..];
            let Some(end) = after.find('}') else { break };
            let body = &after[..end];
            out.push_str(&rest[..start]);
            match Self::resolve_one_ref(db, body, depth, lookups)? {
                Some(resolved) => out.push_str(&resolved),
                // Not a well-formed reference; keep it verbatim.
                None => out.push_str(&rest[start..start + START.len() + end + 1]),
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    /// Resolve the body of one reference (`P@I:<uuid>`). `Ok(None)` if malformed.
    fn resolve_one_ref(
        db: &Database,
        body: &str,
        depth: usize,
        lookups: &mut usize,
    ) -> Result<Option<String>> {
        let mut chars = body.chars();
        let (Some(wanted), Some('@'), Some(search_in), Some(':')) =
            (chars.next(), chars.next(), chars.next(), chars.next())
        else {
            return Ok(None);
        };
        let text = chars.as_str();
        let Some(wanted_field) = Self::ref_field_name(wanted) else {
            return Ok(None);
        };
        let search_in = search_in.to_ascii_uppercase();
        let search_field = Self::ref_field_name(search_in);
        if search_field.is_none() && search_in != 'I' {
            return Ok(None);
        }

        let target = db.iter_all_entries().find(|e| match search_field {
            // Like KeePass, match the first entry whose field contains the text.
            Some(f) => e
                .get(f)
                .is_some_and(|v| v.to_lowercase().contains(&text.to_lowercase())),
            None => e
                .id()
                .to_string()
                .replace('-', "")
                .eq_ignore_ascii_case(text),
        });
        let target = target.ok_or_else(|| FnoxError::ProviderSecretNotFound {
            provider: "KeePass".to_string(),
            secret: format!("{{REF:{body}}}"),
            hint: "The entry referenced by this KeePass field reference was not found".to_string(),
            url: "https://fnox.jdx.dev/providers/keepass".to_string(),
        })?;
        let raw = target
            .get(wanted_field)
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "KeePass".to_string(),
                details: format!(
                    "Field '{wanted_field}' not found in the entry referenced by '{{REF:{body}}}'"
                ),
                hint: "Check that the referenced entry has the requested field".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })?;
        if depth >= Self::MAX_REF_DEPTH {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "KeePass".to_string(),
                details: format!(
                    "KeePass field references nested deeper than {}",
                    Self::MAX_REF_DEPTH
                ),
                hint: "Check for circular field references".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            });
        }
        *lookups += 1;
        if *lookups > Self::MAX_REF_LOOKUPS {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "KeePass".to_string(),
                details: format!(
                    "KeePass field references expanded more than {} times",
                    Self::MAX_REF_LOOKUPS
                ),
                hint: "Check for repeated or circular field references".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            });
        }
        Self::resolve_field_refs(db, raw, depth + 1, lookups).map(Some)
    }

    /// Find an entry id by path in the database.
    ///
    /// Path segments before the last name exact-named subgroups to navigate into;
    /// the final segment is searched recursively by entry title inside the
    /// navigated group (matching the pre-0.12 lookup behavior).
    fn find_entry_id(db: &Database, path: &[&str]) -> Option<EntryId> {
        Self::walk_group(db.root(), path)
    }

    fn walk_group(group: GroupRef<'_>, path: &[&str]) -> Option<EntryId> {
        if path.is_empty() {
            return None;
        }
        if path.len() == 1 {
            Self::find_entry_id_by_title(group, path[0])
        } else {
            let subgroup = group.groups().find(|g| g.name == path[0])?;
            Self::walk_group(subgroup, &path[1..])
        }
    }

    /// Recursively search for an entry by title within a group and its subgroups.
    fn find_entry_id_by_title(group: GroupRef<'_>, title: &str) -> Option<EntryId> {
        for entry in group.entries() {
            if entry.get_title() == Some(title) {
                return Some(entry.id());
            }
        }
        for subgroup in group.groups() {
            if let Some(id) = Self::find_entry_id_by_title(subgroup, title) {
                return Some(id);
            }
        }
        None
    }

    /// Walk the group path from the root, creating any missing groups along the
    /// way, and return the id of the deepest group.
    fn navigate_or_create_group_path(db: &mut Database, group_path: &[&str]) -> GroupId {
        let mut current_id = db.root().id();
        for name in group_path {
            let next_id = db
                .group(current_id)
                .expect("current group exists")
                .groups()
                .find(|g| &g.name == name)
                .map(|g| g.id());
            current_id = match next_id {
                Some(id) => id,
                None => {
                    let mut group_mut = db.group_mut(current_id).expect("current group exists");
                    let mut new_group = group_mut.add_group();
                    new_group.name = (*name).to_string();
                    new_group.as_ref().id()
                }
            };
        }
        current_id
    }

    /// Find or create entry by path for writing.
    /// Returns the entry name (title) that was used.
    fn find_or_create_entry(
        db: &mut Database,
        path: &[&str],
        value: &str,
        field: &str,
    ) -> Result<String> {
        if path.is_empty() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "KeePass".to_string(),
                details: "Empty path for entry".to_string(),
                hint: "Provide an entry name or path".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            });
        }

        // Reject writing to Title field as it's used for entry lookups
        if field == "Title" {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "KeePass".to_string(),
                details: "Cannot write to 'Title' field".to_string(),
                hint: "The 'Title' field is used for entry identification. Use a different field name.".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            });
        }

        let entry_name = path[path.len() - 1];
        let group_path = &path[..path.len() - 1];
        let target_group_id = Self::navigate_or_create_group_path(db, group_path);

        // Look for an existing entry by title recursively under target group.
        let existing_id = Self::find_entry_id_by_title(
            db.group(target_group_id).expect("target group exists"),
            entry_name,
        );

        if let Some(eid) = existing_id {
            let mut entry_mut = db.entry_mut(eid).expect("entry exists");
            // Use protected storage for the Password field (in-memory encryption
            // and proper KDBX marking); other fields are unprotected.
            if field == "Password" {
                entry_mut.set_protected(field, value);
            } else {
                entry_mut.set_unprotected(field, value);
            }
        } else {
            let mut group_mut = db.group_mut(target_group_id).expect("target group exists");
            let mut entry_mut = group_mut.add_entry();
            entry_mut.set_unprotected("Title", entry_name);
            if field == "Password" {
                entry_mut.set_protected(field, value);
            } else {
                entry_mut.set_unprotected(field, value);
            }
        }

        Ok(entry_name.to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for KeePassProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let (entry_path, field) = Self::parse_reference(value);

        tracing::debug!(
            "Getting KeePass secret '{}' field '{}' from '{}'",
            entry_path.join("/"),
            field,
            self.database_path.display()
        );

        let db = self.open_database()?;
        let raw = Self::read_field(&db, value)?;
        Self::resolve_refs(&db, &raw)
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        // Parse the key to determine entry path and field
        let (entry_path, field) = Self::parse_reference(key);

        tracing::debug!(
            "Storing KeePass secret '{}' field '{}' in '{}'",
            entry_path.join("/"),
            field,
            self.database_path.display()
        );

        // Check if database exists; if not, create a new one
        let mut db = if self.database_path.exists() {
            self.open_database()?
        } else {
            // Create new KDBX4 database
            tracing::info!(
                "Creating new KeePass database at '{}'",
                self.database_path.display()
            );
            Database::new()
        };

        // Find or create the entry
        let entry_name = Self::find_or_create_entry(&mut db, &entry_path, value, field)?;

        // Save the database
        self.save_database(&db)?;

        tracing::debug!(
            "Successfully stored secret in KeePass entry '{}'",
            entry_name
        );

        // Return the reference to store in config
        Ok(key.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!(
            "Testing connection to KeePass database '{}'",
            self.database_path.display()
        );

        // Verify password is available
        self.get_password()?;

        // Verify keyfile exists if configured
        if let Some(keyfile_path) = &self.keyfile_path
            && !keyfile_path.exists()
        {
            return Err(FnoxError::ProviderApiError {
                provider: "KeePass".to_string(),
                details: format!("Keyfile '{}' does not exist", keyfile_path.display()),
                hint: "Check the keyfile path in your provider configuration".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            });
        }

        // If database exists, verify we can open it
        // If it doesn't exist, that's OK - put_secret will create it
        if self.database_path.exists() {
            self.open_database()?;
            tracing::debug!("KeePass database connection test successful");
        } else {
            tracing::debug!(
                "KeePass database '{}' does not exist yet (will be created on first write)",
                self.database_path.display()
            );
        }

        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &["KEEPASS_PASSWORD", "FNOX_KEEPASS_PASSWORD"]
}

/// Read KeePass password from environment
fn keepass_password() -> Option<String> {
    std::env::var("FNOX_KEEPASS_PASSWORD")
        .or_else(|_| std::env::var("KEEPASS_PASSWORD"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ref_field_name() {
        assert_eq!(KeePassProvider::ref_field_name('p'), Some("Password"));
        assert_eq!(KeePassProvider::ref_field_name('U'), Some("UserName"));
        assert_eq!(KeePassProvider::ref_field_name('I'), None);
    }

    #[test]
    fn test_resolve_field_refs() {
        let mut db = Database::new();
        let src = db.root_mut().add_entry().id();
        {
            let mut e = db.entry_mut(src).unwrap();
            e.set_unprotected("Title", "source");
            e.set_protected("Password", "s3cret");
        }
        let hex = src.to_string().replace('-', "").to_uppercase();
        let by_id = format!("{{REF:P@I:{hex}}}");
        assert_eq!(
            KeePassProvider::resolve_refs(&db, &by_id).unwrap(),
            "s3cret"
        );
        let by_title = "pre-{REF:P@T:source}-post";
        assert_eq!(
            KeePassProvider::resolve_refs(&db, by_title).unwrap(),
            "pre-s3cret-post"
        );
        assert_eq!(
            KeePassProvider::resolve_refs(&db, "plain").unwrap(),
            "plain"
        );
        assert_eq!(
            KeePassProvider::resolve_refs(&db, "{REF:bogus}").unwrap(),
            "{REF:bogus}"
        );

        // A referenced entry missing the wanted field is an error, not "".
        let nf = db.root_mut().add_entry().id();
        db.entry_mut(nf)
            .unwrap()
            .set_unprotected("Title", "nofield");
        assert!(KeePassProvider::resolve_refs(&db, "{REF:P@T:nofield}").is_err());

        // Field searches match case-insensitive substrings.
        assert_eq!(
            KeePassProvider::resolve_refs(&db, "{REF:P@T:SOURC}").unwrap(),
            "s3cret"
        );

        // Repeated references are bounded.
        let rep = db.root_mut().add_entry().id();
        let rep_hex = rep.to_string().replace('-', "");
        {
            let mut e = db.entry_mut(rep).unwrap();
            e.set_unprotected("Title", "rep");
            e.set_unprotected("UserName", "x");
            e.set_unprotected(
                "Password",
                format!("{{REF:U@I:{rep_hex}}}").repeat(KeePassProvider::MAX_REF_LOOKUPS + 1),
            );
        }
        assert!(KeePassProvider::resolve_refs(&db, &format!("{{REF:P@I:{rep_hex}}}")).is_err());

        // Nested and circular references.
        let b = db.root_mut().add_entry().id();
        db.entry_mut(b).unwrap().set_unprotected("Title", "b");
        db.entry_mut(b)
            .unwrap()
            .set_unprotected("Password", "{REF:P@T:source}");
        assert_eq!(
            KeePassProvider::resolve_refs(&db, "{REF:P@T:b}").unwrap(),
            "s3cret"
        );
        db.entry_mut(src)
            .unwrap()
            .set_unprotected("Password", "{REF:P@T:b}");
        assert!(KeePassProvider::resolve_refs(&db, "{REF:P@T:b}").is_err());
        assert!(KeePassProvider::resolve_refs(&db, "{REF:P@T:missing}").is_err());
    }

    #[test]
    fn test_parse_reference_simple() {
        let (path, field) = KeePassProvider::parse_reference("my-entry");
        assert_eq!(path, vec!["my-entry"]);
        assert_eq!(field, "Password");
    }

    #[test]
    fn test_parse_reference_with_field() {
        let (path, field) = KeePassProvider::parse_reference("my-entry/username");
        assert_eq!(path, vec!["my-entry"]);
        assert_eq!(field, "UserName");

        let (path, field) = KeePassProvider::parse_reference("my-entry/password");
        assert_eq!(path, vec!["my-entry"]);
        assert_eq!(field, "Password");

        let (path, field) = KeePassProvider::parse_reference("my-entry/url");
        assert_eq!(path, vec!["my-entry"]);
        assert_eq!(field, "URL");

        let (path, field) = KeePassProvider::parse_reference("my-entry/notes");
        assert_eq!(path, vec!["my-entry"]);
        assert_eq!(field, "Notes");
    }

    #[test]
    fn test_parse_reference_with_group() {
        let (path, field) = KeePassProvider::parse_reference("group/my-entry");
        assert_eq!(path, vec!["group", "my-entry"]);
        assert_eq!(field, "Password");

        let (path, field) = KeePassProvider::parse_reference("group/subgroup/my-entry");
        assert_eq!(path, vec!["group", "subgroup", "my-entry"]);
        assert_eq!(field, "Password");
    }

    #[test]
    fn test_parse_reference_with_group_and_field() {
        let (path, field) = KeePassProvider::parse_reference("group/my-entry/username");
        assert_eq!(path, vec!["group", "my-entry"]);
        assert_eq!(field, "UserName");

        let (path, field) = KeePassProvider::parse_reference("group/subgroup/my-entry/password");
        assert_eq!(path, vec!["group", "subgroup", "my-entry"]);
        assert_eq!(field, "Password");
    }

    fn custom_field_db() -> Database {
        let mut db = Database::new();
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "github");
        entry.set_protected("Password", "pw");
        entry.set_unprotected("Plain", "plain-value");
        entry.set_unprotected("Region", "eu-west-1");
        entry.set_protected("Token", "secret-token");
        let mut group = root.add_group();
        group.name = "github".to_string();
        let mut shadow = group.add_entry();
        shadow.set_unprotected("Title", "Plain");
        shadow.set_protected("Password", "entry-wins");
        db
    }

    #[test]
    fn test_read_custom_fields() {
        let db = custom_field_db();
        assert_eq!(KeePassProvider::read_field(&db, "github").unwrap(), "pw");
        // An entry with the full path as its title wins over a custom field.
        assert_eq!(
            KeePassProvider::read_field(&db, "github/Plain").unwrap(),
            "entry-wins"
        );
        assert_eq!(
            KeePassProvider::read_field(&db, "github/Plain/password").unwrap(),
            "entry-wins"
        );
        assert_eq!(
            KeePassProvider::read_field(&db, "github/Region").unwrap(),
            "eu-west-1"
        );
        assert_eq!(
            KeePassProvider::read_field(&db, "github/Token").unwrap(),
            "secret-token"
        );
    }

    #[test]
    fn test_read_custom_field_is_case_sensitive_and_missing_errors() {
        let db = custom_field_db();
        assert!(KeePassProvider::read_field(&db, "github/token").is_err());
        assert!(KeePassProvider::read_field(&db, "github/Missing").is_err());
    }

    #[test]
    fn test_explicit_standard_field_skips_custom_fallback() {
        let db = custom_field_db();
        // "github/Token" is not an entry, but "/password" is explicit, so no fallback.
        assert!(KeePassProvider::read_field(&db, "github/Token/password").is_err());
    }
}
