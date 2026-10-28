//! Secret files: file contents stored by the path they are deployed to.
//!
//! A `[files]` entry is a secret whose value is a whole file. It is keyed by the
//! path the file belongs at, resolved through the same providers as a secret, and
//! never reaches the environment. Entries can only be declared in the global
//! config, so a cloned project cannot name a path to write.

use crate::config::{Config, EnvMode, IfMissing, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::providers::{ProviderCapability, ProviderConfig, get_provider_resolved};
use crate::secret_resolver;
use crate::settings::Settings;
use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

/// A file stored as a secret and deployed to the path that keys it
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Description of the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Provider that stores the file (age, aws-kms, 1password, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Stored content for the provider: ciphertext for an encryption provider,
    /// or the key at a remote provider. Use `source` instead to keep it in
    /// a separate file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// File holding the stored content that `value` would hold, relative to the
    /// directory of the config file. Keeps large ciphertext out of the config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Path to the config file where this entry was defined (not serialized)
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
}

/// A file entry of the active profiles, with its path normalized
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Absolute path the file is deployed to
    pub path: PathBuf,
    /// The key as written in the config, such as `~/.kube/config`
    pub key: String,
    /// Profile that declares the entry (`default` for the top-level table)
    pub profile: String,
    pub config: FileConfig,
}

/// What `write_file` did
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    Created,
    Updated,
    Unchanged,
}

/// Resolve `.` and `..` lexically, so two spellings of one path compare equal
fn clean(path: &Path) -> PathBuf {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            other => clean.push(other.as_os_str()),
        }
    }
    clean
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|home| clean(&home))
        .ok_or_else(|| FnoxError::Config("Cannot determine the home directory".into()))
}

/// Resolve `raw` to an absolute path without touching the file system.
///
/// `~` and `~/…` start at the home directory. A relative path is taken from
/// `base` when given and rejected otherwise. `.` and `..` are resolved
/// lexically so that two spellings of one path compare equal.
pub fn normalize_path(raw: &str, base: Option<&Path>) -> Result<PathBuf> {
    if raw.is_empty() {
        return Err(FnoxError::Config("A file path cannot be empty".into()));
    }
    let expanded = if raw == "~" {
        home_dir()?
    } else if let Some(rest) = raw
        .strip_prefix("~/")
        .or_else(|| raw.strip_prefix("~\\").filter(|_| cfg!(windows)))
    {
        home_dir()?.join(rest)
    } else {
        PathBuf::from(raw)
    };
    let absolute = if expanded.is_absolute() {
        expanded
    } else if let Some(base) = base {
        base.join(expanded)
    } else {
        return Err(FnoxError::Config(format!(
            "File path '{raw}' must be absolute or start with '~/'"
        )));
    };
    Ok(clean(&absolute))
}

/// The key to store for `path`: `~/…` under the home directory, so a config
/// carries across machines whose home directories differ.
pub fn display_key(path: &Path) -> String {
    let home = home_dir().ok();
    let shown = match home
        .as_deref()
        .and_then(|home| path.strip_prefix(home).ok())
    {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~/{}", rest.to_string_lossy()),
        None => path.to_string_lossy().into_owned(),
    };
    if cfg!(windows) {
        shown.replace('\\', "/")
    } else {
        shown
    }
}

/// A name for a file at a remote provider, such as `kube-config` for `~/.kube/config`
pub fn default_remote_key(path: &Path) -> String {
    let key = display_key(path);
    let name = key
        .trim_start_matches("~/")
        .trim_start_matches('/')
        .split('/')
        .map(|part| part.trim_start_matches('.'))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if name.is_empty() { "file".into() } else { name }
}

impl FileConfig {
    /// Check the shape of an entry
    pub fn validate(&self, key: &str) -> Result<()> {
        if self.value.is_some() && self.source.is_some() {
            return Err(FnoxError::Config(format!(
                "File '{key}' sets both `value` and `source`; use one"
            )));
        }
        if let Some(source) = &self.source {
            let path = Path::new(source);
            let escapes = path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)));
            if source.is_empty() || escapes {
                return Err(FnoxError::Config(format!(
                    "File '{key}' has `source = \"{source}\"`; it must be a relative path inside the config directory"
                )));
            }
        }
        Ok(())
    }

    /// The content the provider is given: `value`, or the contents of `source`
    pub fn stored_value(&self) -> Result<Option<String>> {
        let Some(source) = &self.source else {
            return Ok(self.value.clone());
        };
        let dir = self
            .source_path
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| {
                Config::global_config_path()
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default()
            });
        let path = dir.join(source);
        let read_error = |path: &Path| {
            let path = path.to_path_buf();
            move |source| FnoxError::SecretFileReadFailed { path, source }
        };
        // A symlink inside the config directory must not lead out of it
        let resolved = fs::canonicalize(&path).map_err(read_error(&path))?;
        let inside = fs::canonicalize(&dir).map_err(read_error(&dir))?;
        if !resolved.starts_with(&inside) {
            return Err(FnoxError::Config(format!(
                "File source '{}' leads outside the config directory",
                path.display()
            )));
        }
        fs::read_to_string(&resolved)
            .map(Some)
            .map_err(read_error(&resolved))
    }
}

impl Config {
    /// Reject `files` entries in a config file other than those of the fnox
    /// config directory, which are the user's own.
    pub(crate) fn check_files_location(&self, path: &Path) -> Result<()> {
        let declares =
            !self.files.is_empty() || self.profiles.values().any(|p| !p.files.is_empty());
        if !declares {
            return Ok(());
        }
        let config_dir = crate::env::FNOX_CONFIG_DIR.as_path();
        let canonical = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        if canonical(path).starts_with(canonical(config_dir)) {
            return Ok(());
        }
        Err(FnoxError::Config(format!(
            "{} declares `files`, which are only allowed in the global config ({}); \
             a project config cannot choose which paths fnox writes",
            path.display(),
            Self::global_config_path().display()
        )))
    }

    /// Validate the entries of every table and the keys they are spelled with
    pub(crate) fn validate_files(&self) -> Result<()> {
        let tables = std::iter::once(&self.files).chain(self.profiles.values().map(|p| &p.files));
        for table in tables {
            let mut seen = IndexMap::new();
            for (key, file) in table {
                let path = normalize_path(key, None)?;
                file.validate(key)?;
                if let Some(other) = seen.insert(path, key) {
                    return Err(FnoxError::Config(format!(
                        "Files '{other}' and '{key}' are the same path"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The file entries of the active profiles. Later profiles override earlier
    /// ones, and top-level entries are the base unless `no_defaults` is set.
    pub fn get_files(&self, profiles: &[String]) -> Result<Vec<FileEntry>> {
        let profiles = self.resolve_profiles(profiles)?;
        let has_non_default = profiles.iter().any(|p| p != "default");
        let mut entries: IndexMap<PathBuf, FileEntry> = IndexMap::new();
        let mut add = |profile: &str, table: &IndexMap<String, FileConfig>| -> Result<()> {
            for (key, config) in table {
                let path = normalize_path(key, None)?;
                entries.insert(
                    path.clone(),
                    FileEntry {
                        path,
                        key: key.clone(),
                        profile: profile.to_string(),
                        config: config.clone(),
                    },
                );
            }
            Ok(())
        };
        if !has_non_default || !Settings::get().no_defaults {
            add("default", &self.files)?;
        }
        for profile in profiles.iter().filter(|p| *p != "default") {
            if let Some(profile_config) = self.profiles.get(profile) {
                add(profile, &profile_config.files)?;
            }
        }
        Ok(entries.into_values().collect())
    }

    /// Every file entry of every table, whichever profiles are active
    pub fn declared_files(&self) -> Vec<FileEntry> {
        let tables = std::iter::once(("default", &self.files)).chain(
            self.profiles
                .iter()
                .map(|(name, profile)| (name.as_str(), &profile.files)),
        );
        let mut entries = Vec::new();
        for (profile, table) in tables {
            for (key, config) in table {
                if let Ok(path) = normalize_path(key, None) {
                    entries.push(FileEntry {
                        path,
                        key: key.clone(),
                        profile: profile.to_string(),
                        config: config.clone(),
                    });
                }
            }
        }
        entries
    }

    /// The entry deployed to `path`, given as written on the command line
    pub fn find_file(&self, profiles: &[String], path: &Path) -> Result<Option<FileEntry>> {
        let wanted = cli_path(path)?;
        Ok(self
            .get_files(profiles)?
            .into_iter()
            .find(|entry| entry.path == wanted))
    }
}

/// Normalize a path typed on the command line, relative to the current directory
pub fn cli_path(path: &Path) -> Result<PathBuf> {
    let cwd = std::env::current_dir()
        .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {e}")))?;
    normalize_path(&path.to_string_lossy(), Some(&cwd))
}

/// The plaintext content of a file entry
///
/// Resolved with the providers of the global config only, as `entry` is.
pub async fn resolve_file(profiles: &[String], entry: &FileEntry) -> Result<String> {
    let config = Config::load_global_only()?;
    let mut secret = SecretConfig::new();
    secret.set_provider(entry.config.provider.clone());
    secret.set_value(entry.config.stored_value()?);
    secret.env = Some(EnvMode::Never);
    secret.if_missing = Some(IfMissing::Error);
    secret_resolver::resolve_secret(&config, profiles, &entry.key, &secret)
        .await?
        .ok_or_else(|| FnoxError::Config(format!("File '{}' has no content", entry.key)))
}

/// Store `content` with the provider and return what the config records for it:
/// ciphertext for an encryption provider, or the key at a remote provider.
///
/// Stored with the providers of the global config only.
pub async fn store_content(
    profiles: &[String],
    provider_name: &str,
    remote_key: &str,
    content: &str,
) -> Result<String> {
    let config = Config::load_global_only()?;
    let providers = config.get_providers(profiles)?;
    let provider_config = providers.get(provider_name).ok_or_else(|| {
        FnoxError::Config(format!(
            "Provider '{provider_name}' not found in configuration"
        ))
    })?;
    // `plain` reports Encryption because it hands values through as they are,
    // which would leave a private file readable in the config
    if matches!(provider_config, ProviderConfig::Plain { .. }) {
        return Err(FnoxError::Config(format!(
            "Provider '{provider_name}' can neither encrypt nor store files; \
             use an encryption provider such as age, or a storage provider such as 1password"
        )));
    }
    let provider = get_provider_resolved(&config, profiles, provider_name, provider_config).await?;
    let capabilities = provider.capabilities();
    if capabilities.contains(&ProviderCapability::Encryption) {
        provider.encrypt(content).await
    } else if capabilities.contains(&ProviderCapability::RemoteStorage) {
        provider.put_secret(remote_key, content).await
    } else {
        Err(FnoxError::Config(format!(
            "Provider '{provider_name}' can neither encrypt nor store files; \
             use an encryption provider such as age, or a storage provider such as 1password"
        )))
    }
}

fn read_document(target: &Path) -> Result<toml_edit::DocumentMut> {
    if !target.exists() {
        return Ok(toml_edit::DocumentMut::new());
    }
    let content = fs::read_to_string(target).map_err(|source| FnoxError::ConfigReadFailed {
        path: target.to_path_buf(),
        source,
    })?;
    content.parse().map_err(|e| {
        FnoxError::Config(format!("Failed to parse TOML in {}: {e}", target.display()))
    })
}

fn write_document(target: &Path, doc: &toml_edit::DocumentMut) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            FnoxError::Config(format!(
                "Failed to create config directory '{}': {e}",
                parent.display()
            ))
        })?;
    }
    fs::write(target, doc.to_string()).map_err(|source| FnoxError::ConfigWriteFailed {
        path: target.to_path_buf(),
        source,
    })
}

fn table_for<'a>(doc: &'a mut toml_edit::DocumentMut, profile: &str) -> &'a mut toml_edit::Table {
    use toml_edit::{Item, Table};
    fn child<'a>(parent: &'a mut Table, name: &str) -> &'a mut Table {
        if !parent.get(name).is_some_and(Item::is_table) {
            // An inline table, as in `files = { … }`, becomes a regular one with its entries
            let current = parent.remove(name).unwrap_or_default();
            parent.insert(name, Item::Table(current.into_table().unwrap_or_default()));
        }
        parent[name]
            .as_table_mut()
            .expect("table was just inserted")
    }
    if profile == "default" {
        child(doc.as_table_mut(), "files")
    } else {
        let profiles = child(doc.as_table_mut(), "profiles");
        child(child(profiles, profile), "files")
    }
}

/// The table of `doc` holding the files of `profile`, if there is one
fn existing_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    profile: &str,
) -> Option<&'a mut dyn toml_edit::TableLike> {
    let table = if profile == "default" {
        doc.get_mut("files")
    } else {
        doc.get_mut("profiles")
            .and_then(|p| p.get_mut(profile))
            .and_then(|p| p.get_mut("files"))
    };
    table.and_then(|t| t.as_table_like_mut())
}

/// The tables of `target` that can hold the files of `profile`. A profile file
/// such as `fnox.work.toml` loads its top-level `[files]` as the profile's, so
/// they come first there. Other files keep the default and each profile apart.
fn candidate_profiles<'a>(target: &Path, profile: &'a str) -> Vec<&'a str> {
    if crate::config::profile_name_from_file(target).as_deref() == Some(profile) {
        vec!["default", profile]
    } else {
        vec![profile]
    }
}

/// Record `file` under `key` in the `files` table of `profile` in `target`
pub fn save_entry(target: &Path, profile: &str, key: &str, file: &FileConfig) -> Result<()> {
    use toml_edit::{InlineTable, Item, Value};
    let mut doc = read_document(target)?;
    let candidates = candidate_profiles(target, profile);
    let holder = candidates
        .iter()
        .copied()
        .find(|p| existing_table(&mut doc, p).is_some_and(|t| t.contains_key(key)))
        .unwrap_or(candidates[0]);
    let table = table_for(&mut doc, holder);

    let mut inline = InlineTable::new();
    let fields = [
        ("description", &file.description),
        ("provider", &file.provider),
        ("value", &file.value),
        ("source", &file.source),
    ];
    for (name, value) in fields {
        if let Some(value) = value {
            inline.insert(name, Value::from(value.as_str()));
        }
    }
    table.insert(key, Item::Value(Value::InlineTable(inline)));
    if let Some(mut key) = table.key_mut(key) {
        key.leaf_decor_mut().set_suffix("");
    }
    write_document(target, &doc)
}

/// Remove the entry `key` from the `files` table of `profile` in `target`.
/// Returns whether it was there.
pub fn remove_entry(target: &Path, profile: &str, key: &str) -> Result<bool> {
    if !target.exists() {
        return Ok(false);
    }
    let mut doc = read_document(target)?;
    // Every table, so an entry that sits in two of them is gone from both
    let mut removed = false;
    for p in candidate_profiles(target, profile) {
        if let Some(table) = existing_table(&mut doc, p) {
            removed |= table.remove(key).is_some();
        }
    }
    if removed {
        write_document(target, &doc)?;
    }
    Ok(removed)
}

/// Write `content` to `path` with mode 0600, replacing any file there.
///
/// The content is written to a private temporary file in the same directory and
/// renamed into place, so a reader never sees a partial file and a symlink at
/// `path` is replaced rather than followed.
pub fn write_file(path: &Path, content: &str) -> Result<WriteOutcome> {
    let existing = fs::read_to_string(path).ok();
    let outcome = match &existing {
        None if !path.exists() && path.symlink_metadata().is_err() => WriteOutcome::Created,
        Some(current) if current == content && !is_symlink(path) => WriteOutcome::Unchanged,
        _ => WriteOutcome::Updated,
    };
    let fail =
        |e: std::io::Error| FnoxError::Config(format!("Failed to write {}: {e}", path.display()));
    if outcome == WriteOutcome::Unchanged {
        set_private(path).map_err(fail)?;
        return Ok(outcome);
    }
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| FnoxError::Config(format!("Invalid file path {}", path.display())))?;
    fs::create_dir_all(dir).map_err(fail)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".fnox-")
        .tempfile_in(dir)
        .map_err(fail)?;
    temp.write_all(content.as_bytes())
        .and_then(|_| temp.flush())
        .map_err(fail)?;
    set_private(temp.path()).map_err(fail)?;
    temp.persist(path).map_err(|e| fail(e.error))?;
    Ok(outcome)
}

fn is_symlink(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
}

#[cfg(unix)]
fn set_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let current = fs::metadata(path)?.permissions().mode() & 0o777;
    if current != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_private(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_spellings_of_one_path() {
        let cwd = Path::new("/work");
        assert_eq!(
            normalize_path("/a/b/../c/./d", Some(cwd)).unwrap(),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(
            normalize_path("rel/x", Some(cwd)).unwrap(),
            PathBuf::from("/work/rel/x")
        );
        assert!(normalize_path("rel/x", None).is_err());
        assert!(normalize_path("", None).is_err());
    }

    #[test]
    fn tilde_and_home_are_the_same_path() {
        let Some(home) = dirs::home_dir() else { return };
        assert_eq!(
            normalize_path("~/.kube/config", None).unwrap(),
            home.join(".kube/config")
        );
        assert_eq!(display_key(&home.join(".kube/config")), "~/.kube/config");
        assert_eq!(display_key(Path::new("/etc/hosts")), "/etc/hosts");
    }

    #[test]
    fn remote_key_is_derived_from_the_path() {
        assert_eq!(
            default_remote_key(&dirs::home_dir().unwrap().join(".kube/config")),
            "kube-config"
        );
        assert_eq!(
            default_remote_key(Path::new("/etc/foo.conf")),
            "etc-foo.conf"
        );
    }

    #[test]
    fn source_must_stay_inside_the_config_directory() {
        let file = |source: &str| FileConfig {
            source: Some(source.into()),
            ..Default::default()
        };
        assert!(file("files/kube.age").validate("k").is_ok());
        assert!(file("../kube.age").validate("k").is_err());
        assert!(file("/etc/kube.age").validate("k").is_err());
        let both = FileConfig {
            value: Some("x".into()),
            source: Some("y".into()),
            ..Default::default()
        };
        assert!(both.validate("k").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn write_file_is_private_and_idempotent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/creds");
        assert_eq!(write_file(&path, "a\n").unwrap(), WriteOutcome::Created);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(write_file(&path, "a\n").unwrap(), WriteOutcome::Unchanged);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(write_file(&path, "a\n").unwrap(), WriteOutcome::Unchanged);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(write_file(&path, "b\n").unwrap(), WriteOutcome::Updated);
        assert_eq!(fs::read_to_string(&path).unwrap(), "b\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_file_replaces_a_symlink_instead_of_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        fs::write(&real, "keep").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(write_file(&link, "new").unwrap(), WriteOutcome::Updated);
        assert_eq!(fs::read_to_string(&real).unwrap(), "keep");
        assert!(!is_symlink(&link));
        assert_eq!(fs::read_to_string(&link).unwrap(), "new");
    }

    #[test]
    fn entries_round_trip_through_the_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(
            &target,
            "# keep me\n[providers.age]\ntype = \"age\"\nrecipients = [\"age1x\"]\n",
        )
        .unwrap();
        let file = FileConfig {
            provider: Some("age".into()),
            value: Some("ciphertext".into()),
            ..Default::default()
        };
        save_entry(&target, "work", "~/.kube/config", &file).unwrap();
        save_entry(&target, "default", "~/.npmrc", &file).unwrap();
        let text = fs::read_to_string(&target).unwrap();
        assert!(text.contains("# keep me"));
        let parsed: Config = toml_edit::de::from_str(&text).unwrap();
        assert!(parsed.files.contains_key("~/.npmrc"));
        assert!(parsed.profiles["work"].files.contains_key("~/.kube/config"));
        assert!(remove_entry(&target, "work", "~/.kube/config").unwrap());
        assert!(!remove_entry(&target, "work", "~/.kube/config").unwrap());
    }

    #[test]
    fn profile_files_keep_their_entries_in_the_top_level_table() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("fnox.work.toml");
        fs::write(
            &target,
            "[files.\"~/.a\"]\nprovider = \"age\"\nvalue = \"old\"\n",
        )
        .unwrap();
        let file = FileConfig {
            provider: Some("age".into()),
            value: Some("new".into()),
            ..Default::default()
        };
        save_entry(&target, "work", "~/.a", &file).unwrap();
        save_entry(&target, "work", "~/.b", &file).unwrap();
        let text = fs::read_to_string(&target).unwrap();
        assert!(!text.contains("profiles"), "{text}");
        assert_eq!(text.matches("~/.a").count(), 1, "{text}");
        assert!(remove_entry(&target, "work", "~/.a").unwrap());
        assert!(remove_entry(&target, "work", "~/.b").unwrap());

        // An entry declared in both tables is removed from both
        fs::write(
            &target,
            "[files.\"~/.c\"]\nvalue = \"x\"\n[profiles.work.files.\"~/.c\"]\nvalue = \"y\"\n",
        )
        .unwrap();
        assert!(remove_entry(&target, "work", "~/.c").unwrap());
        assert!(!remove_entry(&target, "work", "~/.c").unwrap());
    }
}
