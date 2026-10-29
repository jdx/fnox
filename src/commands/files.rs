use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::files::{self, FileConfig, FileEntry, WriteOutcome};
use crate::suggest::{find_similar, format_suggestions};

/// Deploy files stored as secrets
///
/// A file is declared under `[files]` in the global config, keyed by the path it
/// belongs at, and stored with the same providers as a secret. It is never an
/// environment variable. Without a subcommand, `fnox files` lists them.
///
/// Store a file with `fnox set --file PATH`, change it with `fnox edit --file
/// PATH`, print it with `fnox get --file PATH`, and write every file of the
/// active profiles to its path with `fnox files write`.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox files", header = "List the files of the active profiles"),
    example(
        "fnox set --file ~/.kube/config",
        header = "Store a file under its path"
    ),
    example("fnox files write", header = "Write the files to their paths"),
    after_long_help = "See also:\n- Secret files: https://fnox.jdx.dev/guide/files"
)]
pub struct FilesCommand {
    #[usage(subcommand)]
    pub action: Option<FilesAction>,
}

#[derive(Debug, usage_rs::Subcommands)]
pub enum FilesAction {
    List(FilesListCommand),
    Write(FilesWriteCommand),
}

impl FilesCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        match &self.action {
            None => FilesListCommand {}.run(cli, config).await,
            Some(FilesAction::List(cmd)) => cmd.run(cli, config).await,
            Some(FilesAction::Write(cmd)) => cmd.run(cli, config).await,
        }
    }
}

/// List the files of the active profiles
///
/// Prints each path, the profile that declares it, and the provider that stores
/// it. It does not read or decrypt the files.
#[derive(Debug, usage_rs::Args)]
#[usage(alias("ls"))]
pub struct FilesListCommand {}

impl FilesListCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profiles = Config::get_profiles(cli.profile.as_slice());
        let entries = config.get_files(&profiles)?;
        if entries.is_empty() {
            println!(
                "No files in profile {}",
                Config::display_profiles(&profiles)
            );
            return Ok(());
        }
        for entry in &entries {
            let provider = entry.config.provider.as_deref().unwrap_or("(default)");
            println!(
                "{}  {}  {}",
                console::style(&entry.key).cyan(),
                console::style(&entry.profile).magenta(),
                console::style(provider).dim()
            );
        }
        Ok(())
    }
}

/// Write the files to their paths
///
/// Decrypts or fetches each file of the active profiles and writes it to the
/// path that keys it, with mode `0600`, replacing whatever is there. A file whose
/// content already matches is left alone. The content is written to a temporary
/// file and renamed into place, so a symlink at the path is replaced, not
/// followed. Every file is resolved before any is written.
///
/// With PATH arguments, only those files are written.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox files write", header = "Write every file of the profile"),
    example(
        "fnox -P work files write ~/.kube/config",
        header = "Write one file from the work profile"
    ),
    example("fnox files write --dry-run", header = "Show what would be written")
)]
pub struct FilesWriteCommand {
    /// Files to write; omit to write all of them
    #[usage(value_hint = usage_rs::ValueHint::FilePath)]
    pub paths: Vec<PathBuf>,

    /// List the files that would be written without resolving or writing them
    #[usage(short = 'n', long)]
    pub dry_run: bool,
}

impl FilesWriteCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profiles = Config::get_profiles(cli.profile.as_slice());
        let mut entries = config.get_files(&profiles)?;
        if !self.paths.is_empty() {
            let wanted = self
                .paths
                .iter()
                .map(|path| files::cli_path(path))
                .collect::<Result<Vec<_>>>()?;
            for (path, raw) in wanted.iter().zip(&self.paths) {
                if !entries.iter().any(|entry| &entry.path == path) {
                    return Err(file_not_found(&config, &profiles, raw, &entries));
                }
            }
            entries.retain(|entry| wanted.contains(&entry.path));
        }
        if entries.is_empty() {
            println!(
                "No files in profile {}",
                Config::display_profiles(&profiles)
            );
            return Ok(());
        }

        if self.dry_run {
            let label = console::style("[dry-run]").yellow().bold();
            for entry in &entries {
                println!("{label} Would write {}", console::style(&entry.key).cyan());
            }
            return Ok(());
        }

        // Resolve everything first so one failure does not leave the rest half-written
        let mut resolved = Vec::with_capacity(entries.len());
        for entry in &entries {
            let content = files::resolve_file(&profiles, entry).await?;
            resolved.push((entry, content));
        }
        for (entry, content) in resolved {
            let outcome = files::write_file(&entry.path, &content)?;
            let check = console::style("✓").green();
            let key = console::style(&entry.key).cyan();
            match outcome {
                WriteOutcome::Created => println!("{check} Wrote {key}"),
                WriteOutcome::Updated => println!("{check} Updated {key}"),
                WriteOutcome::Unchanged => println!("{check} {key} is up to date"),
            }
        }
        Ok(())
    }
}

fn file_not_found(
    _config: &Config,
    profiles: &[String],
    path: &Path,
    entries: &[FileEntry],
) -> FnoxError {
    let shown = path.to_string_lossy();
    let similar = find_similar(&shown, entries.iter().map(|e| e.key.as_str()));
    FnoxError::Config(format!(
        "No file '{shown}' in profile {}{}",
        Config::display_profiles(profiles),
        format_suggestions(&similar).unwrap_or_default()
    ))
}

fn require_entry(config: &Config, profiles: &[String], path: &Path) -> Result<FileEntry> {
    if let Some(entry) = config.find_file(profiles, path)? {
        return Ok(entry);
    }
    let entries = config.get_files(profiles)?;
    Err(file_not_found(config, profiles, path, &entries))
}

/// Settings that only change how fnox authenticates to a store, not which
/// store or item a key names
fn is_access_setting(name: &str) -> bool {
    matches!(name, "auth_command" | "daemon_cache")
        || ["token", "password", "secret"]
            .iter()
            .any(|word| name.contains(word))
}

/// Drop the provider's own access settings. Nested values such as
/// `prefix = { secret = "NAME" }` choose where content is stored, so they stay.
fn strip_access_settings(value: &mut serde_json::Value) {
    let serde_json::Value::Object(map) = value else {
        return;
    };
    map.retain(|name, _| !is_access_setting(name));
    // A provider tagged by variant name keeps its settings one level down
    if map.len() == 1
        && let Some(inner) = map.values_mut().next()
    {
        strip_access_settings(inner);
    }
}

/// How `put_file` stores a file's content
#[derive(Debug, Default)]
pub struct PutOptions {
    /// Provider to store with; default: the entry's provider, then `default_provider`
    pub provider: Option<String>,
    /// Keep the stored content in this file, relative to the config directory
    pub source: Option<String>,
    /// Name at a remote provider
    pub key_name: Option<String>,
    pub description: Option<String>,
    pub dry_run: bool,
}

/// Store `content` as the file at `path`, under `write_profile` of the config
/// that declares it, or of the global config for a new file
pub async fn put_file(
    config: &Config,
    profiles: &[String],
    write_profile: &str,
    path: &Path,
    content: &str,
    opts: PutOptions,
) -> Result<()> {
    let path = files::cli_path(path)?;
    let inherited = config.find_file(profiles, &path)?;
    // Only an entry of the table being written owns a stored file or remote item;
    // an entry of another profile keeps its own when this one overrides it
    let own = inherited.as_ref().filter(|e| e.profile == write_profile);
    let target = own
        .and_then(|e| e.config.source_path.clone())
        .unwrap_or_else(Config::global_config_path);
    let write_stack = vec![write_profile.to_string()];

    let provider_name = match opts
        .provider
        .clone()
        .or_else(|| inherited.as_ref().and_then(|e| e.config.provider.clone()))
    {
        Some(name) => name,
        None => Config::load_global_only()?
            .get_default_provider(&write_stack)?
            .ok_or_else(|| {
                FnoxError::Config(
                    "No provider for the file; pass --provider or set `default_provider`".into(),
                )
            })?,
    };
    let source = opts
        .source
        .clone()
        .or_else(|| own.and_then(|e| e.config.source.clone()));
    let remote_key = opts
        .key_name
        .clone()
        .or_else(|| {
            own.filter(|e| e.config.provider.as_deref() == Some(provider_name.as_str()))
                .and_then(|e| e.config.stored_value().ok().flatten())
        })
        .unwrap_or_else(|| files::default_remote_key(&path));
    // Reuse the spelling the entry has in the table being written
    let key = own
        .map(|e| e.key.clone())
        .unwrap_or_else(|| files::display_key(&path));

    let mut file = FileConfig {
        description: opts.description.clone().or_else(|| {
            inherited
                .as_ref()
                .and_then(|e| e.config.description.clone())
        }),
        provider: Some(provider_name.clone()),
        value: None,
        source: source.clone(),
        source_path: None,
    };
    file.validate(&key)?;

    // Another file must not share this one's remote item or stored file
    let declared = config.declared_files();
    let others = || {
        declared
            .iter()
            .filter(|e| !(e.path == path && e.profile == write_profile))
    };
    // Profiles can configure one provider name differently, such as another prefix
    let trusted = Config::load_global_only()?;
    let settings_in = |profile: &str| {
        let stack = vec![profile.to_string()];
        trusted
            .get_providers(&stack)
            .ok()
            .and_then(|providers| providers.get(provider_name.as_str()).cloned())
            .and_then(|provider| serde_json::to_value(&provider).ok())
            .map(|mut value| {
                // How fnox reaches the store does not change which item a key names
                strip_access_settings(&mut value);
                value.to_string()
            })
    };
    let own_settings = settings_in(write_profile);
    if let Some(other) = others().find(|e| {
        e.config.provider.as_deref() == Some(provider_name.as_str())
            && e.config.stored_value().ok().flatten().as_deref() == Some(remote_key.as_str())
            && settings_in(&e.profile) == own_settings
    }) {
        return Err(FnoxError::Config(format!(
            "'{remote_key}' at provider '{provider_name}' already stores {}; pass --key-name to name another item",
            other.key
        )));
    }
    let source_file = source.as_ref().map(|source| {
        target
            .parent()
            .map(|dir| dir.join(source))
            .unwrap_or_else(|| PathBuf::from(source))
    });
    if let (Some(source), Some(source_file)) = (&source, &source_file) {
        // Writing over a file that is not this entry's own stored content could
        // destroy a config, an identity, or another file's ciphertext
        let owned = own.is_some_and(|e| e.config.source.as_deref() == Some(source.as_str()));
        if !owned && source_file.symlink_metadata().is_ok() {
            return Err(FnoxError::Config(format!(
                "Source '{}' already exists and is not this file's stored content; choose another name",
                source_file.display()
            )));
        }
    }

    // Write through a linked source, and refuse a dangling link before storing
    let source_file = source_file.map(|f| files::resolve_source(&f)).transpose()?;
    if let Some(source_file) = &source_file {
        let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        if canonical(source_file) == canonical(&target) {
            return Err(FnoxError::Config(format!(
                "Source '{}' is the config file {}; choose another name",
                source_file.display(),
                target.display()
            )));
        }
        // A link must not lead to the stored content of another file either
        let resolved = canonical(source_file);
        if let Some(other) = others().find(|e| {
            e.config
                .source_file()
                .is_some_and(|other| canonical(&other) == resolved)
        }) {
            return Err(FnoxError::Config(format!(
                "Source '{}' already stores {}; choose another name",
                source_file.display(),
                other.key
            )));
        }
    }

    if opts.dry_run {
        let label = console::style("[dry-run]").yellow().bold();
        println!(
            "{label} Would store {} with provider {} in {}",
            console::style(&key).cyan(),
            console::style(&provider_name).magenta(),
            console::style(target.display()).dim()
        );
        return Ok(());
    }

    let stored = files::store_content(&write_stack, &provider_name, &remote_key, content).await?;
    match &source_file {
        Some(source_file) => {
            files::write_file(source_file, &stored)?;
        }
        None => file.value = Some(stored),
    }
    files::save_entry(&target, write_profile, &key, &file)?;

    let check = console::style("✓").green();
    println!(
        "{check} Stored file {} with provider {}",
        console::style(&key).cyan(),
        console::style(&provider_name).magenta()
    );
    Ok(())
}

/// `fnox set --file`: store the content of the file at `path`, or of `from_file`
pub async fn set_file(
    cli: &Cli,
    config: &Config,
    path: &Path,
    from_file: Option<&Path>,
    opts: PutOptions,
) -> Result<()> {
    let profiles = Config::get_profiles(cli.profile.as_slice());
    let write_profile = Config::resolve_write_profile(&profiles, cli.write_profile.as_deref())?;
    let read_from = match from_file {
        Some(from) => from.to_path_buf(),
        None => files::cli_path(path)?,
    };
    let content =
        std::fs::read_to_string(&read_from).map_err(|source| FnoxError::SecretFileReadFailed {
            path: read_from.clone(),
            source,
        })?;
    put_file(config, &profiles, &write_profile, path, &content, opts).await
}

/// `fnox get --file`: print the content of the file, verbatim
pub async fn get_file(cli: &Cli, config: &Config, path: &Path) -> Result<()> {
    let profiles = Config::get_profiles(cli.profile.as_slice());
    let entry = require_entry(config, &profiles, path)?;
    let content = files::resolve_file(&profiles, &entry).await?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(content.as_bytes())
        .and_then(|_| stdout.flush())
        .map_err(|e| FnoxError::Config(format!("Failed to write to stdout: {e}")))
}

/// `fnox edit --file`: edit the content of the file in the editor and store the change
pub async fn edit_file(cli: &Cli, config: &Config, path: &Path) -> Result<()> {
    let profiles = Config::get_profiles(cli.profile.as_slice());
    let entry = require_entry(config, &profiles, path)?;
    let original = files::resolve_file(&profiles, &entry).await?;

    let mut temp = tempfile::Builder::new()
        .prefix("fnox-edit-")
        .tempfile()
        .map_err(|e| FnoxError::Config(format!("Failed to create temporary file: {e}")))?;
    // tempfile creates the file with mode 0600 on Unix
    temp.write_all(original.as_bytes())
        .and_then(|_| temp.flush())
        .map_err(|e| FnoxError::Config(format!("Failed to write to temporary file: {e}")))?;
    crate::commands::edit::EditCommand::open_editor(temp.path())?;

    let edited = std::fs::read_to_string(temp.path())
        .map_err(|e| FnoxError::Config(format!("Failed to read temporary file: {e}")))?;
    if edited == original {
        println!("File {} unchanged", console::style(&entry.key).cyan());
        return Ok(());
    }
    // Write the change to the table that declares the entry
    put_file(
        config,
        &profiles,
        &entry.profile,
        &entry.path,
        &edited,
        PutOptions::default(),
    )
    .await
}

/// `fnox remove --file`: remove the entry from the global config
pub fn remove_file(cli: &Cli, config: &Config, path: &Path, dry_run: bool) -> Result<()> {
    let profiles = Config::get_profiles(cli.profile.as_slice());
    let write_profile = Config::resolve_write_profile(&profiles, cli.write_profile.as_deref())?;
    let wanted = files::cli_path(path)?;
    let entry = config
        .get_files(std::slice::from_ref(&write_profile))?
        .into_iter()
        .find(|entry| entry.path == wanted && entry.profile == write_profile)
        .ok_or_else(|| {
            let all = config.get_files(&profiles).unwrap_or_default();
            file_not_found(config, &profiles, path, &all)
        })?;
    // Remove it from the config file that declares it, which may be an import
    let target = entry
        .config
        .source_path
        .clone()
        .unwrap_or_else(Config::global_config_path);
    if dry_run {
        let label = console::style("[dry-run]").yellow().bold();
        println!(
            "{label} Would remove file {} from {}",
            console::style(&entry.key).cyan(),
            console::style(target.display()).dim()
        );
        return Ok(());
    }
    if !files::remove_entry(&target, &write_profile, &entry.key)? {
        return Err(file_not_found(config, &profiles, path, &[]));
    }
    println!(
        "{} Removed file {}",
        console::style("✓").green(),
        console::style(&entry.key).cyan()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn access_settings_are_dropped_but_store_settings_stay() {
        let mut provider = json!({
            "type": "aws-ps",
            "token": "t",
            "daemon_cache": true,
            "prefix": { "secret": "PERSONAL_PREFIX" },
        });
        strip_access_settings(&mut provider);
        assert_eq!(
            provider,
            json!({ "type": "aws-ps", "prefix": { "secret": "PERSONAL_PREFIX" } })
        );

        let mut tagged = json!({ "vault": { "address": "a", "token": "t" } });
        strip_access_settings(&mut tagged);
        assert_eq!(tagged, json!({ "vault": { "address": "a" } }));
    }
}
