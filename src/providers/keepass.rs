use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use async_trait::async_trait;
use keepass::DatabaseKey;
use keepass::db::{Database, Entry, Group, Node, Value};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Provider that reads and writes secrets from KeePass database files (.kdbx)
pub struct KeePassProvider {
    database_path: PathBuf,
    keyfile_path: Option<PathBuf>,
    password: Option<String>,
}

impl KeePassProvider {
    pub fn new(database: String, keyfile: Option<String>, password: Option<String>) -> Self {
        Self {
            database_path: PathBuf::from(shellexpand::tilde(&database).to_string()),
            keyfile_path: keyfile.map(|k| PathBuf::from(shellexpand::tilde(&k).to_string())),
            password,
        }
    }

    /// Get the password from environment variable or config
    fn get_password(&self) -> Result<String> {
        // Priority: env var > config
        if let Some(password) = keepass_password() {
            return Ok(password);
        }

        if let Some(password) = &self.password {
            return Ok(password.clone());
        }

        Err(FnoxError::ProviderAuthFailed {
            provider: "KeePass".to_string(),
            details: "Database password not set".to_string(),
            hint: "Set FNOX_KEEPASS_PASSWORD or KEEPASS_PASSWORD environment variable, or configure password in provider config".to_string(),
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

    /// Find an entry by path in the database
    /// If path has multiple parts, navigate through groups
    /// If path has one part, search all entries for matching title
    fn find_entry<'a>(group: &'a Group, path: &[&str]) -> Option<&'a Entry> {
        if path.is_empty() {
            return None;
        }

        if path.len() == 1 {
            // Search for entry by title in this group and all subgroups
            let entry_name = path[0];
            Self::find_entry_by_title(group, entry_name)
        } else {
            // Navigate to subgroup first
            let group_name = path[0];
            for node in &group.children {
                if let Node::Group(subgroup) = node
                    && subgroup.name == group_name
                {
                    return Self::find_entry(subgroup, &path[1..]);
                }
            }
            None
        }
    }

    /// Search for an entry by title in a group and all its subgroups
    fn find_entry_by_title<'a>(group: &'a Group, title: &str) -> Option<&'a Entry> {
        for node in &group.children {
            match node {
                Node::Entry(entry) => {
                    if entry.get_title() == Some(title) {
                        return Some(entry);
                    }
                }
                Node::Group(subgroup) => {
                    if let Some(entry) = Self::find_entry_by_title(subgroup, title) {
                        return Some(entry);
                    }
                }
            }
        }
        None
    }

    /// Search for an entry by title in a group and all its subgroups (mutable version)
    fn find_entry_by_title_mut<'a>(group: &'a mut Group, title: &str) -> Option<&'a mut Entry> {
        // First find the index of the entry or subgroup containing it
        let mut found_entry_idx = None;
        let mut found_in_subgroup_idx = None;

        for (i, node) in group.children.iter().enumerate() {
            match node {
                Node::Entry(entry) if entry.get_title() == Some(title) => {
                    found_entry_idx = Some(i);
                    break;
                }
                Node::Group(subgroup) => {
                    // Check if entry exists in this subgroup (read-only check)
                    if Self::find_entry_by_title(subgroup, title).is_some() {
                        found_in_subgroup_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }

        // Now access mutably based on what we found
        if let Some(idx) = found_entry_idx {
            if let Node::Entry(entry) = &mut group.children[idx] {
                return Some(entry);
            }
        } else if let Some(idx) = found_in_subgroup_idx
            && let Node::Group(subgroup) = &mut group.children[idx]
        {
            return Self::find_entry_by_title_mut(subgroup, title);
        }
        None
    }

    /// Find or create entry by path for writing
    /// Returns the entry name (title) that was used
    fn find_or_create_entry(
        group: &mut Group,
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

        // Use Protected for Password field (in-memory encryption and proper KDBX marking)
        let field_value = if field == "Password" {
            Value::Protected(value.as_bytes().into())
        } else {
            Value::Unprotected(value.to_string())
        };

        if path.len() == 1 {
            // Create or update entry in this group or any subgroup (recursive search)
            let entry_name = path[0];

            // Look for existing entry recursively
            if let Some(entry) = Self::find_entry_by_title_mut(group, entry_name) {
                // Update existing entry
                entry.fields.insert(field.to_string(), field_value);
                return Ok(entry_name.to_string());
            }

            // Create new entry in current group
            let mut entry = Entry::new();
            entry.fields.insert(
                "Title".to_string(),
                Value::Unprotected(entry_name.to_string()),
            );
            entry.fields.insert(field.to_string(), field_value);
            group.children.push(Node::Entry(entry));
            Ok(entry_name.to_string())
        } else {
            // Navigate to or create subgroup
            let group_name = path[0];

            // Look for existing group
            for node in &mut group.children {
                if let Node::Group(subgroup) = node
                    && subgroup.name == group_name
                {
                    return Self::find_or_create_entry(subgroup, &path[1..], value, field);
                }
            }

            // Create new group
            let mut new_group = Group::new(group_name);
            let result = Self::find_or_create_entry(&mut new_group, &path[1..], value, field)?;
            group.children.push(Node::Group(new_group));
            Ok(result)
        }
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

        let entry = Self::find_entry(&db.root, &entry_path).ok_or_else(|| {
            FnoxError::ProviderSecretNotFound {
                provider: "KeePass".to_string(),
                secret: entry_path.join("/"),
                hint: "Check that the entry exists in the database".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            }
        })?;

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
                hint: "Available fields: password, username, url, notes, title".to_string(),
                url: "https://fnox.jdx.dev/providers/keepass".to_string(),
            })
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
            Database::new(keepass::config::DatabaseConfig::default())
        };

        // Find or create the entry
        let entry_name = Self::find_or_create_entry(&mut db.root, &entry_path, value, field)?;

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
}
