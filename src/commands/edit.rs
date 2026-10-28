use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use indexmap::IndexMap;
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, Table, Value};

use crate::commands::Cli;
use crate::commands::set::SetCommand;
use crate::config::{Config, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::generate::GenerateKind;
use crate::providers::{ProviderCapability, get_provider_resolved};
use crate::secret_resolver;
use crate::suggest::{find_similar, format_suggestions};

/// Header added to temporary edit file for user reference
const TEMP_FILE_HEADER: &str = "\
# FNOX EDIT - Decrypted Secrets
# This is a temporary file with decrypted secret values.
# Secrets marked as READ-ONLY cannot be modified (from 1Password, Bitwarden, etc.)
# After you save and close this file, fnox will re-encrypt changed secrets.
# DO NOT share this file as it contains plaintext secrets!

";

/// Edit the config file, or one secret, with values decrypted
///
/// Without KEY, decrypts or fetches every secret in the config file, across all
/// profiles, into a private temporary copy and opens it in `$EDITOR` (then
/// `$VISUAL`, then `vi`, or `notepad` on Windows). When the editor exits, fnox
/// stores each new or changed value with its provider and writes the file back,
/// keeping your comments and formatting. Unchanged values keep their existing
/// ciphertext.
///
/// With KEY, only that secret's resolved value is written, raw and without TOML,
/// to a private temporary file for the active profile. If you change it, fnox
/// stores the new value with the secret's provider as `fnox set --from-file`
/// does, keeping its other settings. The other secrets are not decrypted.
///
/// The editor command may include arguments, such as `EDITOR="code --wait"`.
/// Secrets from read-only providers are shown but cannot be changed. fnox edits
/// the file named by `-c` (default: `fnox.toml` in the current directory).
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox edit", header = "Edit fnox.toml in your editor"),
    example("EDITOR=nano fnox edit", header = "Use a specific editor"),
    example(
        "EDITOR=\"code --wait\" fnox edit",
        header = "Use an editor command with arguments"
    ),
    example(
        "fnox -P work edit KUBECONFIG",
        header = "Edit one secret from the work profile"
    ),
    after_long_help = "See also:\n- Configuration reference: https://fnox.jdx.dev/reference/configuration"
)]
pub struct EditCommand {
    /// Secret to edit on its own; omit to edit the whole config file
    pub key: Option<String>,
}

/// Split a Windows editor command on whitespace, where double quotes group words
/// and backslashes stay literal so paths like `C:\Tools\Vim\vim.exe -n` survive.
fn split_windows_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut in_quotes = false;
    for c in command.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                in_word = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            c => {
                current.push(c);
                in_word = true;
            }
        }
    }
    if in_quotes {
        return None;
    }
    if in_word {
        words.push(current);
    }
    Some(words)
}

/// Represents a secret with its metadata for tracking during editing
#[derive(Debug, Clone)]
struct SecretEntry {
    /// The profile this secret belongs to ("default" for top-level secrets)
    profile: String,
    /// The secret key (environment variable name)
    key: String,
    /// The original secret config from the config file
    original_config: SecretConfig,
    /// The decrypted/fetched plaintext value (if available)
    plaintext_value: Option<String>,
    /// Whether this secret is from a read-only provider (can't be modified)
    is_read_only: bool,
    /// The provider name used for this secret
    provider_name: Option<String>,
}

impl EditCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if let Some(key) = &self.key {
            return self.edit_one(cli, config, key).await;
        }
        let profile = Config::get_profiles(cli.profile.as_slice());
        tracing::debug!(
            "Starting enhanced edit with profile: {}",
            Config::display_profiles(&profile)
        );

        // Step 1: Load raw TOML with toml_edit to preserve formatting
        let toml_content =
            fs::read_to_string(&cli.config).map_err(|source| FnoxError::ConfigReadFailed {
                path: cli.config.clone(),
                source,
            })?;
        let doc = toml_content
            .parse::<DocumentMut>()
            .map_err(|e| FnoxError::Config(format!("Failed to parse TOML: {}", e)))?;

        // Step 2: Collect all secrets from all profiles
        let mut all_secrets = Vec::new();

        // Collect secrets from top-level [secrets] section
        if !config.secrets.is_empty() {
            self.collect_secrets(&config, "default", &config.secrets, &mut all_secrets)
                .await?;
        }

        // Collect secrets from all [profiles.*] sections
        for (profile_name, profile_config) in &config.profiles {
            if !profile_config.secrets.is_empty() {
                self.collect_secrets(
                    &config,
                    profile_name,
                    &profile_config.secrets,
                    &mut all_secrets,
                )
                .await?;
            }
        }

        // Step 3: Decrypt/fetch all secrets (force error mode in edit)
        tracing::debug!("Decrypting {} secrets", all_secrets.len());
        let mut secrets_by_profile: IndexMap<String, IndexMap<String, SecretConfig>> =
            IndexMap::new();
        for secret_entry in &all_secrets {
            // In edit mode, override if_missing to "error" to get the actual error
            let mut edit_secret_config = secret_entry.original_config.clone();
            edit_secret_config.if_missing = Some(crate::config::IfMissing::Error);
            secrets_by_profile
                .entry(secret_entry.profile.clone())
                .or_default()
                .insert(secret_entry.key.clone(), edit_secret_config);
        }

        let mut resolved_by_profile: IndexMap<String, IndexMap<String, Option<String>>> =
            IndexMap::new();
        for (profile_name, secrets) in secrets_by_profile {
            let profile_stack = vec![profile_name.clone()];
            let resolved =
                secret_resolver::resolve_secrets_batch(&config, &profile_stack, &secrets).await?;
            resolved_by_profile.insert(profile_name, resolved);
        }

        for secret_entry in &mut all_secrets {
            secret_entry.plaintext_value = resolved_by_profile
                .get(&secret_entry.profile)
                .and_then(|resolved| resolved.get(&secret_entry.key))
                .cloned()
                .flatten();
        }

        // Step 4: Create temporary file with decrypted TOML
        let temp_file = self.create_decrypted_temp_file(&doc, &all_secrets)?;
        let temp_path = temp_file.path().to_path_buf();

        // Step 5: Open editor on temp file
        tracing::debug!("Opening editor on temporary file");
        Self::open_editor(&temp_path)?;

        // Step 6: Read and parse modified temp file
        tracing::debug!("Reading modified temporary file");
        let modified_content = fs::read_to_string(&temp_path)
            .map_err(|e| FnoxError::Config(format!("Failed to read temporary file: {}", e)))?;
        let mut modified_doc = modified_content
            .parse::<DocumentMut>()
            .map_err(|e| FnoxError::Config(format!("Invalid TOML after edit: {}", e)))?;

        // Step 7: Re-encrypt secrets in the modified document
        // This preserves all user edits (comments, formatting, non-secret config)
        tracing::debug!("Re-encrypting secrets in modified document");

        // Parse a fresh config from the modified content to recognize new providers
        // Strip the temp header first as it's not valid TOML
        let modified_toml = Self::strip_temp_header(&modified_content);
        let edited_config: Config = toml_edit::de::from_str(&modified_toml)
            .map_err(|e| FnoxError::Config(format!("Invalid configuration after edit: {}", e)))?;
        // Resolve the edited file's imports so providers defined there are available
        // for encryption, without keeping settings the user removed in the editor
        let config_dir = std::path::absolute(&cli.config)
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_default();
        let mut modified_config = edited_config.with_imports(&config_dir)?;
        // Providers that only the global, parent or local override layers define are
        // still needed to re-encrypt existing secrets. Anything sourced from the
        // edited file or its original imports is not restored, so removals stick.
        let mut own_files = vec![std::path::absolute(&cli.config).unwrap_or_default()];
        if let Some(imports) = doc.get("import").and_then(|i| i.as_array()) {
            own_files.extend(
                imports
                    .iter()
                    .filter_map(|i| i.as_str())
                    .map(|i| crate::config_path::resolve_relative_to_dir(i, Some(&config_dir))),
            );
        }
        modified_config.inherit_outer_layers(&config, &own_files);

        self.reencrypt_secrets(&modified_config, &mut modified_doc, &all_secrets)
            .await?;

        // Step 8: Save the modified config (preserves all user edits)
        // Strip the temporary file header comments before saving
        let output = Self::strip_temp_header(&modified_doc.to_string());
        fs::write(&cli.config, output).map_err(|source| FnoxError::ConfigWriteFailed {
            path: cli.config.clone(),
            source,
        })?;

        let check = console::style("✓").green();
        let styled_config = console::style(cli.config.display()).cyan();
        println!("{check} Configuration file {styled_config} updated with re-encrypted secrets");

        Ok(())
    }

    /// Edit a single secret's raw value in the editor
    async fn edit_one(&self, cli: &Cli, config: Config, key: &str) -> Result<()> {
        let profile = Config::get_profiles(cli.profile.as_slice());
        tracing::debug!(
            "Editing secret '{}' with profile: {}",
            key,
            Config::display_profiles(&profile)
        );

        let profile_secrets = config.get_secrets(&profile)?;
        let secret_config = profile_secrets.get(key).ok_or_else(|| {
            let similar = find_similar(key, profile_secrets.keys().map(|s| s.as_str()));
            FnoxError::SecretNotFound {
                key: key.to_string(),
                profile: Config::display_profiles(&profile),
                config_path: config.secret_sources.get(key).cloned(),
                suggestion: format_suggestions(&similar),
            }
        })?;

        let provider_name = match secret_config.provider() {
            Some(name) => Some(name.to_string()),
            None => config.get_default_provider(&profile)?,
        };
        if let Some(provider_name) = &provider_name {
            let providers = config.get_providers(&profile)?;
            if let Some(provider_config) = providers.get(provider_name) {
                let provider =
                    get_provider_resolved(&config, &profile, provider_name, provider_config)
                        .await?;
                let caps = provider.capabilities();
                if caps.contains(&ProviderCapability::RemoteRead)
                    && !caps.contains(&ProviderCapability::Encryption)
                    && !caps.contains(&ProviderCapability::RemoteStorage)
                {
                    return Err(FnoxError::Config(format!(
                        "Cannot modify read-only secret '{key}' from provider '{provider_name}'"
                    )));
                }
            }
        }

        // Edit the full stored value, not a `json_path`/`line` selection of it or a
        // `fnox sync` cache of it, and like `fnox edit` surface the real error
        // instead of applying if_missing. Resolve what the secret interpolates or
        // needs for provider auth too, but nothing unrelated.
        let mut edit_config = secret_config.clone();
        edit_config.if_missing = Some(crate::config::IfMissing::Error);
        edit_config.json_path = None;
        edit_config.line = None;
        edit_config.sync = None;
        let mut all = profile_secrets.clone();
        all.insert(key.to_string(), edit_config);
        let batch =
            secret_resolver::dependency_closure(&config, &profile, &all, &[key.to_string()])?;
        let original = secret_resolver::resolve_secrets_batch(&config, &profile, &batch)
            .await?
            .swap_remove(key)
            .flatten()
            .ok_or_else(|| FnoxError::Config(format!("Secret '{key}' has no value to edit")))?;

        let mut temp_file = tempfile::Builder::new()
            .prefix("fnox-edit-")
            .tempfile()
            .map_err(|e| FnoxError::Config(format!("Failed to create temporary file: {}", e)))?;
        // tempfile creates the file with mode 0600 on Unix
        temp_file
            .write_all(original.as_bytes())
            .and_then(|_| temp_file.flush())
            .map_err(|e| FnoxError::Config(format!("Failed to write to temporary file: {}", e)))?;
        let temp_path = temp_file.path().to_path_buf();

        Self::open_editor(&temp_path)?;

        let mut edited = fs::read_to_string(&temp_path)
            .map_err(|e| FnoxError::Config(format!("Failed to read temporary file: {}", e)))?;
        // Editors often append a final newline the value did not have
        if !original.ends_with('\n')
            && let Some(stripped) = edited.strip_suffix('\n')
        {
            edited = stripped.strip_suffix('\r').unwrap_or(stripped).to_string();
        }

        if edited == original {
            println!("Secret {} unchanged", console::style(key).cyan());
            return Ok(());
        }
        fs::write(&temp_path, &edited)
            .map_err(|e| FnoxError::Config(format!("Failed to write temporary file: {}", e)))?;

        // A `fnox sync --local-file` cache copy lives in the personal override file;
        // the value belongs to the shared definition it caches
        let cache = secret_config
            .sync
            .as_ref()
            .is_some_and(|sync| !sync.local_source)
            .then(|| secret_config.clone());
        let source_path = if cache.is_some() {
            Config::load_smart_without_local_sync(&cli.config)?
                .get_secret(&profile, key)
                .ok()
                .flatten()
                .and_then(|s| s.source_path.clone())
        } else {
            secret_config.source_path.clone()
        };
        let write_profile = Config::resolve_write_profile(&profile, cli.write_profile.as_deref())?;
        let set = SetCommand {
            key: key.to_string(),
            value: None,
            description: None,
            global: false,
            key_name: None,
            dry_run: false,
            // Store with the provider the value was read from, even when
            // `--write-profile` points at a profile with another default
            provider: provider_name,
            base64_encode: false,
            default: None,
            force: false,
            from_file: Some(temp_path),
            generate: false,
            generate_type: GenerateKind::Password,
            if_missing: None,
            length: None,
            show: false,
        };
        // Write the new value back to the file that defines the secret, not the
        // file `fnox set` would pick for the current directory. A profile file such
        // as `fnox.prod.toml` holds its profile's secrets at the top level, so unless
        // it is the write profile's own file `fnox set` picks the file itself.
        match source_path {
            Some(path)
                if !crate::config::is_profile_file(&path)
                    || crate::config::profile_name_from_file(&path).as_deref()
                        == Some(write_profile.as_str()) =>
            {
                let config = Self::config_for_file(config, &path)?;
                set.run_at(cli, config, path).await?;
            }
            _ => set.run(cli, config).await?,
        }

        // The old cache would keep shadowing the shared value it was copied from
        if let Some(cache) = cache
            && let Some(cache_path) = &cache.source_path
        {
            Self::drop_sync_cache(cache_path, key, &cache)?;
        }
        Ok(())
    }

    /// The config to encrypt a value with when it is stored in `path`: the providers
    /// that file sees, not ones the current directory overrides (say, with other age
    /// recipients), or the value is unreadable wherever that file is used alone.
    fn config_for_file(config: Config, path: &Path) -> Result<Config> {
        // The global config is the base of every project
        if path == Config::global_config_path() {
            return Config::load_smart(path);
        }
        // A project's own config, found from a directory above the current one. Other
        // files, such as profile files and imports, are overlays that need the
        // merged config.
        if crate::config::local_override_filename(path).is_some()
            && let Some(dir) = path.parent().map(|dir| {
                if dir.file_name().is_some_and(|name| name == ".config") {
                    dir.parent().unwrap_or(dir)
                } else {
                    dir
                }
            })
            && let Ok(cwd) = env::current_dir()
            && cwd != dir
            && cwd.starts_with(dir)
        {
            return Config::load_discovered_from(dir, true);
        }
        Ok(config)
    }

    /// Remove the `fnox sync --local-file` cache entry of `key` from `path`
    fn drop_sync_cache(path: &Path, key: &str, cache: &SecretConfig) -> Result<()> {
        let content = fs::read_to_string(path).map_err(|source| FnoxError::ConfigReadFailed {
            path: path.to_path_buf(),
            source,
        })?;
        let mut doc = content
            .parse::<DocumentMut>()
            .map_err(|e| FnoxError::Config(format!("Failed to parse TOML: {}", e)))?;
        let secrets = match &cache.source_profile {
            Some(profile) if cache.source_is_profile => doc
                .get_mut("profiles")
                .and_then(|p| p.get_mut(profile))
                .and_then(|p| p.get_mut("secrets")),
            _ => doc.get_mut("secrets"),
        };
        let Some(secrets) = secrets.and_then(|s| s.as_table_like_mut()) else {
            return Ok(());
        };
        let is_cache = secrets
            .get(key)
            .and_then(|entry| entry.get("sync"))
            .is_some_and(|sync| sync.get("local_source").and_then(|v| v.as_bool()) != Some(true));
        if is_cache {
            secrets.remove(key);
            fs::write(path, doc.to_string()).map_err(|source| FnoxError::ConfigWriteFailed {
                path: path.to_path_buf(),
                source,
            })?;
        }
        Ok(())
    }

    /// Pick the editor command: `$EDITOR`, then `$VISUAL` (each ignored when empty
    /// or blank), then `vi` (`notepad` on Windows).
    fn editor_command() -> String {
        ["EDITOR", "VISUAL"]
            .iter()
            .filter_map(|name| env::var(name).ok())
            .find(|v| !v.trim().is_empty())
            .unwrap_or_else(|| {
                if cfg!(target_os = "windows") {
                    "notepad".to_string()
                } else {
                    "vi".to_string()
                }
            })
    }

    /// Split an editor command such as `code --wait` into the program and its
    /// arguments, using shell quoting rules.
    fn split_editor_command(editor: &str) -> Result<(String, Vec<String>)> {
        // A path to an editor, such as `C:\Program Files\Editor\edit.exe`, is a
        // program on its own, not words to split
        if std::path::Path::new(editor).is_file() {
            return Ok((editor.to_string(), Vec::new()));
        }
        let mut words = if cfg!(windows) {
            split_windows_words(editor)
        } else {
            shlex::split(editor)
        }
        .filter(|w| !w.is_empty())
        .ok_or_else(|| {
            FnoxError::Config(format!("Invalid editor command (check quoting): {editor}"))
        })?;
        let program = words.remove(0);
        Ok((program, words))
    }

    /// Open `path` in the user's editor and wait for it to exit
    fn open_editor(path: &std::path::Path) -> Result<()> {
        let editor = Self::editor_command();
        let (program, args) = Self::split_editor_command(&editor)?;

        #[cfg(windows)]
        let program_path: std::path::PathBuf =
            which::which(&program).unwrap_or_else(|_| program.clone().into());
        #[cfg(not(windows))]
        let program_path = &program;

        let status = Command::new(program_path)
            .args(&args)
            .arg(path)
            .status()
            .map_err(|e| FnoxError::EditorLaunchFailed {
                editor: editor.clone(),
                source: e,
            })?;

        if !status.success() {
            // No exit code means the editor was killed by a signal
            return Err(FnoxError::EditorExitFailed {
                editor,
                status: status.code().unwrap_or(-1),
            });
        }
        Ok(())
    }

    /// Collect secrets from a specific secrets table (top-level or profile)
    async fn collect_secrets(
        &self,
        config: &Config,
        profile: &str,
        secrets: &IndexMap<String, SecretConfig>,
        all_secrets: &mut Vec<SecretEntry>,
    ) -> Result<()> {
        let profile_stack = vec![profile.to_string()];
        for (key, secret_config) in secrets {
            // Determine provider and check if read-only
            let provider_name = if let Some(prov) = secret_config.provider() {
                Some(prov.to_string())
            } else {
                config.get_default_provider(&profile_stack)?
            };

            let (is_read_only, resolved_provider_name) = if let Some(ref prov_name) = provider_name
            {
                let providers = config.get_providers(&profile_stack)?;
                if let Some(provider_config) = providers.get(prov_name) {
                    let provider =
                        get_provider_resolved(config, &profile_stack, prov_name, provider_config)
                            .await?;
                    let capabilities = provider.capabilities();
                    let is_read_only = capabilities.contains(&ProviderCapability::RemoteRead)
                        && !capabilities.contains(&ProviderCapability::Encryption)
                        && !capabilities.contains(&ProviderCapability::RemoteStorage);
                    (is_read_only, Some(prov_name.clone()))
                } else {
                    (false, provider_name)
                }
            } else {
                (false, None)
            };

            all_secrets.push(SecretEntry {
                profile: profile.to_string(),
                key: key.clone(),
                original_config: secret_config.clone(),
                plaintext_value: None,
                is_read_only,
                provider_name: resolved_provider_name,
            });
        }
        Ok(())
    }

    /// Create a temporary file with decrypted secrets
    fn create_decrypted_temp_file(
        &self,
        doc: &DocumentMut,
        all_secrets: &[SecretEntry],
    ) -> Result<NamedTempFile> {
        let mut temp_file = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .map_err(|e| FnoxError::Config(format!("Failed to create temporary file: {}", e)))?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = temp_file
                .as_file()
                .metadata()
                .map_err(|e| FnoxError::Config(format!("Failed to get file metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            temp_file
                .as_file()
                .set_permissions(perms)
                .map_err(|e| FnoxError::Config(format!("Failed to set file permissions: {}", e)))?;
        }

        // Clone the document and replace encrypted values with plaintext
        let mut decrypted_doc = doc.clone();

        // Create a map of secrets by (profile, key) for quick lookup to avoid collisions
        let secrets_map: HashMap<_, _> = all_secrets
            .iter()
            .map(|s| ((s.profile.clone(), s.key.clone()), s))
            .collect();

        // Replace values in [secrets] section
        if let Some(secrets_table) = decrypted_doc
            .get_mut("secrets")
            .and_then(|item| item.as_table_mut())
        {
            self.replace_secrets_in_table(secrets_table, "default", &secrets_map)?;
        }

        // Replace values in [profiles.*] sections
        if let Some(profiles_table) = decrypted_doc
            .get_mut("profiles")
            .and_then(|item| item.as_table_mut())
        {
            for (profile_name, profile_item) in profiles_table.iter_mut() {
                let profile_name_str = profile_name.to_string();
                if let Some(profile_table) = profile_item.as_table_mut()
                    && let Some(secrets_table) = profile_table
                        .get_mut("secrets")
                        .and_then(|item| item.as_table_mut())
                {
                    self.replace_secrets_in_table(secrets_table, &profile_name_str, &secrets_map)?;
                }
            }
        }

        // Add header comment
        let header = format!("{}{}", TEMP_FILE_HEADER, decrypted_doc);

        temp_file
            .write_all(header.as_bytes())
            .map_err(|e| FnoxError::Config(format!("Failed to write to temporary file: {}", e)))?;

        temp_file
            .flush()
            .map_err(|e| FnoxError::Config(format!("Failed to flush temporary file: {}", e)))?;

        Ok(temp_file)
    }

    /// Replace encrypted secret values with plaintext in a TOML table
    fn replace_secrets_in_table(
        &self,
        secrets_table: &mut Table,
        profile: &str,
        secrets_map: &HashMap<(String, String), &SecretEntry>,
    ) -> Result<()> {
        for (key, value) in secrets_table.iter_mut() {
            let key_string = key.to_string();
            let lookup_key = (profile.to_string(), key_string.clone());
            if let Some(secret_entry) = secrets_map.get(&lookup_key) {
                // Try inline table first (KEY = { provider = "...", value = "..." })
                if let Some(inline_table) = value.as_inline_table_mut() {
                    if let Some(plaintext) = &secret_entry.plaintext_value {
                        inline_table.insert("value", Value::from(plaintext.as_str()));
                    }
                } else if let Some(table) = value.as_table_mut() {
                    // Handle regular table format ([secrets.KEY])
                    if let Some(plaintext) = &secret_entry.plaintext_value {
                        table.insert("value", toml_edit::value(plaintext.as_str()));
                    }
                }

                // Note: We can't easily add inline comments to tables in toml_edit
                // The read-only status will be enforced when processing changes
            }
        }
        Ok(())
    }

    /// Re-encrypt secrets in the modified document
    /// This preserves all user edits (comments, formatting, non-secret config)
    async fn reencrypt_secrets(
        &self,
        config: &Config,
        modified_doc: &mut DocumentMut,
        all_secrets: &[SecretEntry],
    ) -> Result<()> {
        // Create a map of secrets by (profile, key) to avoid collisions
        let secrets_map: HashMap<_, _> = all_secrets
            .iter()
            .map(|s| ((s.profile.clone(), s.key.clone()), s))
            .collect();

        // Process [secrets] section
        if let Some(secrets_table) = modified_doc
            .get_mut("secrets")
            .and_then(|item| item.as_table_mut())
        {
            self.reencrypt_secrets_table(config, secrets_table, "default", &secrets_map)
                .await?;
        }

        // Process [profiles.*] sections
        if let Some(profiles_table) = modified_doc
            .get_mut("profiles")
            .and_then(|item| item.as_table_mut())
        {
            // Collect profile names first to avoid borrow issues
            let profile_names: Vec<_> = profiles_table.iter().map(|(k, _)| k.to_string()).collect();

            for profile_name in profile_names {
                if let Some(profile_item) = profiles_table.get_mut(&profile_name)
                    && let Some(profile_table) = profile_item.as_table_mut()
                    && let Some(secrets_table) = profile_table
                        .get_mut("secrets")
                        .and_then(|item| item.as_table_mut())
                {
                    self.reencrypt_secrets_table(
                        config,
                        secrets_table,
                        &profile_name,
                        &secrets_map,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    /// Re-encrypt secrets in a specific secrets table
    async fn reencrypt_secrets_table(
        &self,
        config: &Config,
        secrets_table: &mut Table,
        secret_profile: &str,
        secrets_map: &HashMap<(String, String), &SecretEntry>,
    ) -> Result<()> {
        let profile_stack = vec![secret_profile.to_string()];
        // Collect keys first to avoid borrow issues when mutating
        let keys: Vec<_> = secrets_table.iter().map(|(k, _)| k.to_string()).collect();

        for key_str in keys {
            let lookup_key = (secret_profile.to_string(), key_str.clone());

            // Get the current value from the table
            let Some(value) = secrets_table.get_mut(&key_str) else {
                continue;
            };

            // Extract plaintext value and provider from the value
            let (plaintext, explicit_provider) = if let Some(inline_table) = value.as_inline_table()
            {
                let plaintext = inline_table.get("value").and_then(|v| v.as_str());
                let provider = inline_table.get("provider").and_then(|v| v.as_str());
                (plaintext, provider.map(String::from))
            } else if let Some(table) = value.as_table() {
                let plaintext = table.get("value").and_then(|v| v.as_str());
                let provider = table.get("provider").and_then(|v| v.as_str());
                (plaintext, provider.map(String::from))
            } else {
                continue;
            };

            let Some(plaintext) = plaintext else {
                continue;
            };

            // Check if this is an existing secret or a new one
            if let Some(secret_entry) = secrets_map.get(&lookup_key) {
                // Existing secret - check if read-only
                if secret_entry.is_read_only {
                    // Verify it wasn't changed
                    if Some(plaintext) != secret_entry.plaintext_value.as_deref() {
                        return Err(FnoxError::Config(format!(
                            "Cannot modify read-only secret '{}' from provider '{}'",
                            key_str,
                            secret_entry
                                .provider_name
                                .as_ref()
                                .unwrap_or(&"unknown".to_string())
                        )));
                    }
                    // Read-only and unchanged - restore original encrypted value
                    if let Some(original_value) = secret_entry.original_config.value() {
                        Self::set_secret_value(value, original_value);
                    }
                    continue;
                }

                // Check if the value or provider changed
                // Compare explicit provider fields (not resolved provider names)
                // to avoid false positives when secrets use default provider
                let value_changed = Some(plaintext) != secret_entry.plaintext_value.as_deref();
                let provider_changed =
                    explicit_provider.as_deref() != secret_entry.original_config.provider();

                if !value_changed && !provider_changed {
                    // Nothing changed - restore original encrypted value to avoid version control churn
                    if let Some(original_value) = secret_entry.original_config.value() {
                        Self::set_secret_value(value, original_value);
                    }
                    continue;
                }

                // Value or provider changed - re-encrypt
                // If explicit provider is set, use it; otherwise use default provider for this secret's profile
                tracing::debug!("Secret '{}' changed, re-encrypting", key_str);
                let provider_to_use = if let Some(ref prov) = explicit_provider {
                    Some(prov.clone())
                } else {
                    config.get_default_provider(&profile_stack)?
                };
                let encrypted_value = if let Some(provider_name) = provider_to_use {
                    let providers = config.get_providers(&profile_stack)?;
                    if let Some(provider_config) = providers.get(&provider_name) {
                        let provider = get_provider_resolved(
                            config,
                            &profile_stack,
                            &provider_name,
                            provider_config,
                        )
                        .await?;
                        provider.put_secret(&key_str, plaintext).await?
                    } else {
                        return Err(FnoxError::Config(format!(
                            "Provider '{}' not found for secret '{}'",
                            provider_name, key_str
                        )));
                    }
                } else {
                    plaintext.to_string()
                };

                Self::set_secret_value(value, &encrypted_value);
            } else {
                // New secret added by user
                tracing::debug!("New secret '{}' detected, encrypting", key_str);

                // Determine provider to use (from this secret's profile)
                let provider_name = if let Some(prov) = explicit_provider {
                    prov
                } else if let Some(default_prov) = config.get_default_provider(&profile_stack)? {
                    default_prov
                } else {
                    // No provider - keep as plaintext
                    tracing::warn!(
                        "No provider specified for new secret '{}', storing as plaintext",
                        key_str
                    );
                    continue;
                };

                // Encrypt with the provider from this secret's profile
                let providers = config.get_providers(&profile_stack)?;
                let Some(provider_config) = providers.get(&provider_name) else {
                    return Err(FnoxError::Config(format!(
                        "Provider '{}' not found for new secret '{}'",
                        provider_name, key_str
                    )));
                };

                let provider =
                    get_provider_resolved(config, &profile_stack, &provider_name, provider_config)
                        .await?;
                let encrypted_value = provider.put_secret(&key_str, plaintext).await?;

                Self::set_secret_value(value, &encrypted_value);
            }
        }

        Ok(())
    }

    /// Helper to set the value field in a secret (handles both inline table and table formats)
    fn set_secret_value(item: &mut toml_edit::Item, value: &str) {
        if let Some(inline_table) = item.as_inline_table_mut() {
            inline_table.insert("value", Value::from(value));
        } else if let Some(table) = item.as_table_mut() {
            table.insert("value", toml_edit::value(value));
        }
    }

    /// Strip the temporary file header that was added for user reference
    fn strip_temp_header(content: &str) -> String {
        // Only strip if the content starts with our exact header
        // This avoids accidentally removing user comments that happen to match patterns
        content
            .strip_prefix(TEMP_FILE_HEADER)
            .unwrap_or(content)
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_editor_command_into_program_and_args() {
        let (program, args) = EditCommand::split_editor_command("code --wait").unwrap();
        assert_eq!(program, "code");
        assert_eq!(args, ["--wait"]);

        let quoted = if cfg!(windows) {
            r#"vim -n -c "set ft=toml""#
        } else {
            "vim -n -c 'set ft=toml'"
        };
        let (program, args) = EditCommand::split_editor_command(quoted).unwrap();
        assert_eq!(program, "vim");
        assert_eq!(args, ["-n", "-c", "set ft=toml"]);
    }

    #[test]
    fn windows_split_keeps_backslashes_and_honors_quotes() {
        assert_eq!(
            split_windows_words(r#"C:\Tools\Vim\vim.exe -n"#).unwrap(),
            [r"C:\Tools\Vim\vim.exe", "-n"]
        );
        assert_eq!(
            split_windows_words(r#""C:\Program Files\Code\code.exe" --wait"#).unwrap(),
            [r"C:\Program Files\Code\code.exe", "--wait"]
        );
    }

    #[test]
    fn rejects_unbalanced_quotes_in_editor_command() {
        let unbalanced = if cfg!(windows) {
            r#"vim "oops"#
        } else {
            "vim 'oops"
        };
        assert!(EditCommand::split_editor_command(unbalanced).is_err());
    }
}
