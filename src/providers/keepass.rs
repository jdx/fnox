use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use async_trait::async_trait;
use keepass::DatabaseKey;
use keepass::db::{Database, Entry, Group, Node, Value};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

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
        if let Some(password) = KEEPASS_PASSWORD.as_ref() {
            return Ok(password.clone());
        }

        if let Some(password) = &self.password {
            return Ok(password.clone());
        }

        Err(FnoxError::Provider(
            "KeePass password not set. Set FNOX_KEEPASS_PASSWORD or KEEPASS_PASSWORD environment variable, or configure password in provider config.".to_string(),
        ))
    }

    /// Build the database key from password and optional keyfile
    fn build_key(&self) -> Result<DatabaseKey> {
        let password = self.get_password()?;
        let mut key = DatabaseKey::new();

        // Add password
        key = key.with_password(&password);

        // Add keyfile if configured
        if let Some(keyfile_path) = &self.keyfile_path {
            let mut keyfile = File::open(keyfile_path).map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to open KeePass keyfile '{}': {}",
                    keyfile_path.display(),
                    e
                ))
            })?;
            key = key
                .with_keyfile(&mut keyfile)
                .map_err(|e| FnoxError::Provider(format!("Failed to read KeePass keyfile: {e}")))?;
        }

        Ok(key)
    }

    /// Open and decrypt the database
    fn open_database(&self) -> Result<Database> {
        let file = File::open(&self.database_path).map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to open KeePass database '{}': {}",
                self.database_path.display(),
                e
            ))
        })?;
        let mut reader = BufReader::new(file);
        let key = self.build_key()?;

        Database::open(&mut reader, key)
            .map_err(|e| FnoxError::Provider(format!("Failed to open KeePass database: {e}")))
    }

    /// Save the database back to disk
    fn save_database(&self, db: &Database) -> Result<()> {
        // Write to a temporary file first, then atomically rename to avoid data loss
        // if the save fails partway through (File::create truncates immediately)
        let parent_dir = self.database_path.parent().unwrap_or(Path::new("."));
        let temp_path = parent_dir.join(format!(
            ".{}.tmp",
            self.database_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ));

        let file = File::create(&temp_path).map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to create temporary KeePass database file '{}': {}",
                temp_path.display(),
                e
            ))
        })?;
        let mut writer = BufWriter::new(file);
        let key = self.build_key()?;

        // Save to temp file
        if let Err(e) = db.save(&mut writer, key) {
            // Clean up temp file on failure
            let _ = std::fs::remove_file(&temp_path);
            return Err(FnoxError::Provider(format!(
                "Failed to save KeePass database: {e}"
            )));
        }

        // Flush buffer to file
        if let Err(e) = writer.flush() {
            let _ = std::fs::remove_file(&temp_path);
            return Err(FnoxError::Provider(format!(
                "Failed to flush KeePass database to disk: {e}"
            )));
        }

        // Sync to disk to ensure durability before rename
        if let Err(e) = writer.get_ref().sync_all() {
            let _ = std::fs::remove_file(&temp_path);
            return Err(FnoxError::Provider(format!(
                "Failed to sync KeePass database to disk: {e}"
            )));
        }

        // Atomically rename temp file to target (preserves original on failure)
        std::fs::rename(&temp_path, &self.database_path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            FnoxError::Provider(format!(
                "Failed to rename temporary KeePass database file: {e}"
            ))
        })
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
            && let Node::Group(subgroup) = &mut group.children[idx] {
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
            return Err(FnoxError::Provider(
                "Empty path for KeePass entry".to_string(),
            ));
        }

        // Reject writing to Title field as it's used for entry lookups
        if field == "Title" {
            return Err(FnoxError::Provider(
                "Cannot write to 'Title' field as it is used for entry identification. Use a different field name.".to_string(),
            ));
        }

        if path.len() == 1 {
            // Create or update entry in this group or any subgroup (recursive search)
            let entry_name = path[0];

            // Look for existing entry recursively
            if let Some(entry) = Self::find_entry_by_title_mut(group, entry_name) {
                // Update existing entry
                entry
                    .fields
                    .insert(field.to_string(), Value::Unprotected(value.to_string()));
                return Ok(entry_name.to_string());
            }

            // Create new entry in current group
            let mut entry = Entry::new();
            entry.fields.insert(
                "Title".to_string(),
                Value::Unprotected(entry_name.to_string()),
            );
            entry
                .fields
                .insert(field.to_string(), Value::Unprotected(value.to_string()));
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

    async fn get_secret(&self, value: &str, _key_file: Option<&Path>) -> Result<String> {
        let (entry_path, field) = Self::parse_reference(value);

        tracing::debug!(
            "Getting KeePass secret '{}' field '{}' from '{}'",
            entry_path.join("/"),
            field,
            self.database_path.display()
        );

        let db = self.open_database()?;

        let entry = Self::find_entry(&db.root, &entry_path).ok_or_else(|| {
            FnoxError::Provider(format!(
                "Entry '{}' not found in KeePass database",
                entry_path.join("/")
            ))
        })?;

        entry.get(field).map(|s| s.to_string()).ok_or_else(|| {
            FnoxError::Provider(format!(
                "Field '{}' not found in entry '{}'",
                field,
                entry_path.join("/")
            ))
        })
    }

    async fn put_secret(&self, key: &str, value: &str, _key_file: Option<&Path>) -> Result<String> {
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

        // Try to open the database
        self.open_database()?;

        tracing::debug!("KeePass database connection test successful");
        Ok(())
    }
}

/// Environment variable for KeePass password
static KEEPASS_PASSWORD: LazyLock<Option<String>> = LazyLock::new(|| {
    std::env::var("FNOX_KEEPASS_PASSWORD")
        .or_else(|_| std::env::var("KEEPASS_PASSWORD"))
        .ok()
});

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
