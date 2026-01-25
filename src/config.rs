use crate::env;
use crate::error::{FnoxError, Result};
use crate::source_registry;
use crate::spanned::SpannedValue;
use clap::ValueEnum;
use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use strum::VariantNames;

/// Returns all config filenames in load order (first = lowest priority, last = highest priority).
///
/// Order: main configs → profile configs → local configs
/// Within each group, dotfiles come first (higher priority than non-dotfiles).
pub fn all_config_filenames(profile: Option<&str>) -> Vec<String> {
    let mut files = vec!["fnox.toml".to_string(), ".fnox.toml".to_string()];
    if let Some(p) = profile.filter(|p| *p != "default") {
        files.push(format!("fnox.{p}.toml"));
        files.push(format!(".fnox.{p}.toml"));
    }
    files.push("fnox.local.toml".to_string());
    files.push(".fnox.local.toml".to_string());
    files
}

// Re-export ProviderConfig from providers module
pub use crate::providers::ProviderConfig;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Import paths to other config files
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub import: Vec<String>,

    /// Root configuration - stops recursion at this level
    #[serde(default, skip_serializing_if = "is_false")]
    pub root: bool,

    /// Provider configurations (for default profile)
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub providers: IndexMap<String, ProviderConfig>,

    /// Default provider name for default profile
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_provider: Option<SpannedValue<String>>,

    /// Default profile secrets (top level)
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub secrets: IndexMap<String, SecretConfig>,

    /// Named profiles
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub profiles: IndexMap<String, ProfileConfig>,

    /// Age encryption key file path (optional, can also be set via env var or CLI flag)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_key_file: Option<PathBuf>,

    /// Default if_missing behavior for all secrets in this config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_missing: Option<IfMissing>,

    /// Whether to prompt for authentication when provider auth fails (default: true in TTY)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_auth: Option<bool>,

    /// Track which config file each provider came from (not serialized)
    #[serde(skip)]
    pub provider_sources: HashMap<String, PathBuf>,

    /// Track which config file each secret came from (not serialized)
    #[serde(skip)]
    pub secret_sources: HashMap<String, PathBuf>,

    /// Track which config file the default_provider came from (not serialized)
    #[serde(skip)]
    pub default_provider_source: Option<PathBuf>,
}

/// Configuration for a single secret
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretConfig {
    /// Description of the secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// What to do if the secret is missing (error, warn, or ignore)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_missing: Option<IfMissing>,

    /// Default value to use if provider fails or secret is not found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,

    /// Provider to fetch from (age, aws-kms, 1password, aws, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<SpannedValue<String>>,

    /// Value for the provider (secret name, encrypted blob, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<SpannedValue<String>>,

    /// Path to the config file where this secret was defined (not serialized)
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
}

/// Configuration for a profile
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// Provider configurations for this profile
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub providers: IndexMap<String, ProviderConfig>,

    /// Default provider name for this profile
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_provider: Option<SpannedValue<String>>,

    /// Secrets for this profile
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub secrets: IndexMap<String, SecretConfig>,

    /// Track which config file each provider came from (not serialized)
    #[serde(skip)]
    pub provider_sources: HashMap<String, PathBuf>,

    /// Track which config file each secret came from (not serialized)
    #[serde(skip)]
    pub secret_sources: HashMap<String, PathBuf>,

    /// Track which config file the default_provider came from (not serialized)
    #[serde(skip)]
    pub default_provider_source: Option<PathBuf>,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, ValueEnum, VariantNames,
)]
#[serde(rename_all = "lowercase")]
pub enum IfMissing {
    Error,
    Warn,
    Ignore,
}

impl Config {
    /// Load configuration using the appropriate strategy
    pub fn load_smart<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();

        // If the path is one of the default config filenames, use recursive loading
        let default_filenames = all_config_filenames(None);
        if default_filenames.iter().any(|f| path_ref == Path::new(f)) {
            Self::load_with_recursion(path_ref)
        } else {
            // For explicit paths, resolve relative paths against current directory first
            let resolved_path = if path_ref.is_relative() {
                env::current_dir()
                    .map_err(|e| {
                        FnoxError::Config(format!("Failed to get current directory: {}", e))
                    })?
                    .join(path_ref)
            } else {
                path_ref.to_path_buf()
            };
            // For explicit paths, use direct loading
            Self::load(resolved_path)
        }
    }

    /// Load configuration from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        use miette::{NamedSource, SourceSpan};

        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|source| FnoxError::ConfigReadFailed {
            path: path.to_path_buf(),
            source,
        })?;

        // Register the source for error reporting
        source_registry::register(path, content.clone());

        let mut config: Config = toml_edit::de::from_str(&content).map_err(|e| {
            // Try to create a source-aware error with span highlighting
            if let Some(span) = e.span() {
                FnoxError::ConfigParseErrorWithSource {
                    message: e.message().to_string(),
                    src: Arc::new(NamedSource::new(
                        path.display().to_string(),
                        Arc::new(content),
                    )),
                    span: SourceSpan::new(span.start.into(), span.end - span.start),
                }
            } else {
                // Fall back to the basic error if no span available
                FnoxError::ConfigParseError { source: e }
            }
        })?;

        // Set source paths for all secrets and providers
        config.set_source_paths(path);

        Ok(config)
    }

    /// Load configuration with recursive directory search and merging
    fn load_with_recursion<P: AsRef<Path>>(_start_path: P) -> Result<Self> {
        // Start from current working directory and search upwards
        let current_dir = env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {}", e)))?;

        match Self::load_recursive(&current_dir, false) {
            Ok((_config, found)) if !found => {
                // No config file was found anywhere in the directory tree
                Err(FnoxError::ConfigNotFound {
                    message: format!(
                        "No configuration file found in {} or any parent directory",
                        current_dir.display()
                    ),
                    help: "Run 'fnox init' to create a configuration file".to_string(),
                })
            }
            Ok((config, _)) => Ok(config),
            Err(e) => Err(e),
        }
    }

    /// Recursively search for fnox.toml files and merge them
    /// Returns (config, found_any) where found_any indicates if any config file was found
    fn load_recursive(dir: &Path, found_any: bool) -> Result<(Self, bool)> {
        // Get current profile from Settings (respects: CLI flag > Env var > Default)
        let profile = crate::settings::Settings::get().profile.clone();
        let filenames = all_config_filenames(Some(&profile));

        // Load all existing config files in order (later files override earlier ones)
        let mut config = Self::new();
        let mut found = found_any;

        for filename in &filenames {
            let path = dir.join(filename);
            if path.exists() {
                let file_config = Self::load(&path)?;
                config = Self::merge_configs(config, file_config)?;
                found = true;
            }
        }

        // If this config marks root, stop recursion but still load global config
        if config.root {
            // Load imports if any
            for import_path in &config.import.clone() {
                let import_config = Self::load_import(import_path, dir)?;
                config = Self::merge_configs(import_config, config)?;
            }
            // Load global config as the base even for root configs
            let (global_config, global_found) = Self::load_global()?;
            if global_found {
                config = Self::merge_configs(global_config, config)?;
                found = true;
            }
            return Ok((config, found));
        }

        // Load imports first (they get overridden by local config)
        for import_path in &config.import.clone() {
            let import_config = Self::load_import(import_path, dir)?;
            config = Self::merge_configs(import_config, config)?;
        }

        // If we have a parent directory, recurse up and merge
        if let Some(parent_dir) = dir.parent() {
            let (parent_config, parent_found) = Self::load_recursive(parent_dir, found)?;
            config = Self::merge_configs(parent_config, config)?;
            found = found || parent_found;
        } else {
            // At the filesystem root, try to load global config as base
            let (global_config, global_found) = Self::load_global()?;
            if global_found {
                config = Self::merge_configs(global_config, config)?;
                found = true;
            }
        }

        Ok((config, found))
    }

    /// Get the path to the global config file
    pub fn global_config_path() -> PathBuf {
        env::FNOX_CONFIG_DIR.join("config.toml")
    }

    /// Load global configuration from FNOX_CONFIG_DIR/config.toml
    /// This is the lowest priority config, overridden by all project-level configs
    fn load_global() -> Result<(Self, bool)> {
        let global_config_path = Self::global_config_path();

        if global_config_path.exists() {
            tracing::debug!(
                "Loading global config from {}",
                global_config_path.display()
            );
            let config = Self::load(&global_config_path)?;
            Ok((config, true))
        } else {
            Ok((Self::new(), false))
        }
    }

    /// Load an imported config file
    fn load_import(import_path: &str, base_dir: &Path) -> Result<Self> {
        let path = PathBuf::from(import_path);

        // Handle relative paths - they're relative to the base config's directory
        let absolute_path = if path.is_absolute() {
            path
        } else {
            base_dir.join(path)
        };

        if !absolute_path.exists() {
            return Err(FnoxError::Config(format!(
                "Import file not found: {}",
                absolute_path.display()
            )));
        }

        Self::load(&absolute_path)
    }

    /// Merge two configs, with second config taking precedence
    fn merge_configs(base: Config, overlay: Config) -> Result<Config> {
        let mut merged = base;

        // Merge imports (overlay takes precedence, but keep unique paths)
        for import_path in overlay.import {
            if !merged.import.contains(&import_path) {
                merged.import.push(import_path);
            }
        }

        // root flag: if either is true, result is true
        merged.root = merged.root || overlay.root;

        // Merge age_key_file (overlay takes precedence)
        if overlay.age_key_file.is_some() {
            merged.age_key_file = overlay.age_key_file;
        }

        // Merge if_missing (overlay takes precedence)
        if overlay.if_missing.is_some() {
            merged.if_missing = overlay.if_missing;
        }

        // Merge prompt_auth (overlay takes precedence)
        if overlay.prompt_auth.is_some() {
            merged.prompt_auth = overlay.prompt_auth;
        }

        // Merge default_provider and its source (overlay takes precedence)
        if overlay.default_provider.is_some() {
            merged.default_provider = overlay.default_provider;
            merged.default_provider_source = overlay.default_provider_source;
        }

        // Merge providers (overlay takes precedence)
        for (name, provider) in overlay.providers {
            merged.providers.insert(name, provider);
        }

        // Merge provider sources (overlay takes precedence)
        for (name, source) in overlay.provider_sources {
            merged.provider_sources.insert(name, source);
        }

        // Merge secrets (overlay takes precedence)
        for (name, secret) in overlay.secrets {
            merged.secrets.insert(name, secret);
        }

        // Merge secret sources (overlay takes precedence)
        for (name, source) in overlay.secret_sources {
            merged.secret_sources.insert(name, source);
        }

        // Merge profiles (overlay takes precedence)
        for (name, profile) in overlay.profiles {
            if let Some(existing_profile) = merged.profiles.get_mut(&name) {
                // Merge existing profile
                for (provider_name, provider) in profile.providers {
                    existing_profile.providers.insert(provider_name, provider);
                }
                for (provider_name, source) in &profile.provider_sources {
                    existing_profile
                        .provider_sources
                        .insert(provider_name.clone(), source.clone());
                }
                for (secret_name, secret) in profile.secrets {
                    existing_profile.secrets.insert(secret_name, secret);
                }
                for (secret_name, source) in &profile.secret_sources {
                    existing_profile
                        .secret_sources
                        .insert(secret_name.clone(), source.clone());
                }
                // Merge default_provider and its source (overlay takes precedence)
                if profile.default_provider.is_some() {
                    existing_profile.default_provider = profile.default_provider;
                    existing_profile.default_provider_source = profile.default_provider_source;
                }
            } else {
                merged.profiles.insert(name, profile);
            }
        }

        Ok(merged)
    }

    /// Save configuration to a file
    /// Uses toml_edit to preserve insertion order from IndexMap
    /// and format secrets as inline tables
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // Clone and clean up empty profiles before saving
        let mut clean_config = self.clone();
        clean_config
            .profiles
            .retain(|_, profile| !profile.is_empty());

        // First serialize with to_string_pretty to get proper structure
        let pretty_string = toml_edit::ser::to_string_pretty(&clean_config)?;

        // Parse it back as a document so we can modify it
        let mut doc = pretty_string
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| FnoxError::Config(format!("Failed to parse TOML: {}", e)))?;

        // Convert secrets to inline tables
        Self::convert_secrets_to_inline(&mut doc)?;

        fs::write(path.as_ref(), doc.to_string()).map_err(|source| {
            FnoxError::ConfigWriteFailed {
                path: path.as_ref().to_path_buf(),
                source,
            }
        })?;
        Ok(())
    }

    /// Convert all tables in [secrets] and [profiles.*.secrets] to inline tables
    fn convert_secrets_to_inline(doc: &mut toml_edit::DocumentMut) -> Result<()> {
        use toml_edit::{InlineTable, Item};

        // Convert top-level [secrets]
        if let Some(secrets_item) = doc.get_mut("secrets")
            && let Some(secrets_table) = secrets_item.as_table_mut()
        {
            let keys: Vec<String> = secrets_table.iter().map(|(k, _)| k.to_string()).collect();
            for key in keys {
                if let Some(item) = secrets_table.get_mut(&key)
                    && let Some(table) = item.as_table()
                {
                    let mut inline = InlineTable::new();
                    for (k, v) in table.iter() {
                        if let Some(value) = v.as_value() {
                            inline.insert(k, value.clone());
                        }
                    }
                    inline.fmt();
                    *item = Item::Value(toml_edit::Value::InlineTable(inline));
                }
            }
        }

        // Convert [profiles.*.secrets]
        if let Some(profiles_item) = doc.get_mut("profiles")
            && let Some(profiles_table) = profiles_item.as_table_mut()
        {
            let profile_names: Vec<String> =
                profiles_table.iter().map(|(k, _)| k.to_string()).collect();
            for profile_name in profile_names {
                if let Some(profile_item) = profiles_table.get_mut(&profile_name)
                    && let Some(profile_table) = profile_item.as_table_mut()
                    && let Some(secrets_item) = profile_table.get_mut("secrets")
                    && let Some(secrets_table) = secrets_item.as_table_mut()
                {
                    let keys: Vec<String> =
                        secrets_table.iter().map(|(k, _)| k.to_string()).collect();
                    for key in keys {
                        if let Some(item) = secrets_table.get_mut(&key)
                            && let Some(table) = item.as_table()
                        {
                            let mut inline = InlineTable::new();
                            for (k, v) in table.iter() {
                                if let Some(value) = v.as_value() {
                                    inline.insert(k, value.clone());
                                }
                            }
                            inline.fmt();
                            *item = Item::Value(toml_edit::Value::InlineTable(inline));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Save a single secret update back to its source file
    /// Always saves to the default_target (local config file), creating a local
    /// override if the secret exists in a parent config. This aligns with the
    /// hierarchical config model where child configs override parent configs.
    ///
    /// This method preserves comments and formatting in the TOML file by
    /// directly manipulating the document AST rather than re-serializing.
    pub fn save_secret_to_source(
        &self,
        secret_name: &str,
        secret_config: &SecretConfig,
        profile: &str,
        default_target: &Path,
    ) -> Result<()> {
        use toml_edit::{DocumentMut, Item, Value};

        let target_file = default_target.to_path_buf();

        // Load existing document or create new one (preserves comments)
        let mut doc = if target_file.exists() {
            let content =
                fs::read_to_string(&target_file).map_err(|source| FnoxError::ConfigReadFailed {
                    path: target_file.clone(),
                    source,
                })?;
            content
                .parse::<DocumentMut>()
                .map_err(|e| FnoxError::Config(format!("Failed to parse TOML: {}", e)))?
        } else {
            DocumentMut::new()
        };

        // Get or create the secrets table
        let secrets_table = if profile == "default" {
            if doc.get("secrets").is_none() {
                doc["secrets"] = Item::Table(toml_edit::Table::new());
            }
            doc["secrets"].as_table_mut().unwrap()
        } else {
            if doc.get("profiles").is_none() {
                doc["profiles"] = Item::Table(toml_edit::Table::new());
            }
            let profiles = doc["profiles"].as_table_mut().unwrap();
            if profiles.get(profile).is_none() {
                profiles[profile] = Item::Table(toml_edit::Table::new());
            }
            let profile_table = profiles[profile].as_table_mut().unwrap();
            if profile_table.get("secrets").is_none() {
                profile_table["secrets"] = Item::Table(toml_edit::Table::new());
            }
            profile_table["secrets"].as_table_mut().unwrap()
        };

        // Update/insert the secret as inline table
        let inline = secret_config.to_inline_table();
        secrets_table[secret_name] = Item::Value(Value::InlineTable(inline));

        // Remove trailing space from key to match format: KEY= { ... } instead of KEY = { ... }
        if let Some(mut key) = secrets_table.key_mut(secret_name) {
            key.leaf_decor_mut().set_suffix("");
        }

        // Write back (preserves all comments and formatting)
        fs::write(&target_file, doc.to_string()).map_err(|source| {
            FnoxError::ConfigWriteFailed {
                path: target_file,
                source,
            }
        })?;

        Ok(())
    }

    /// Create a new default configuration
    pub fn new() -> Self {
        Self {
            import: Vec::new(),
            root: false,
            providers: IndexMap::new(),
            default_provider: None,
            secrets: IndexMap::new(),
            profiles: IndexMap::new(),
            age_key_file: None,
            if_missing: None,
            prompt_auth: None,
            provider_sources: HashMap::new(),
            secret_sources: HashMap::new(),
            default_provider_source: None,
        }
    }

    /// Get the profile to use (from flag or env var, defaulting to "default")
    pub fn get_profile(profile_flag: Option<&str>) -> String {
        profile_flag
            .map(String::from)
            .or_else(|| (*env::FNOX_PROFILE).clone())
            .unwrap_or_else(|| "default".to_string())
    }

    /// Determine if we should prompt for authentication when provider auth fails.
    /// Priority: env var > config > default (true)
    /// Returns true only if prompting is enabled AND we're in a TTY.
    pub fn should_prompt_auth(&self) -> bool {
        // Check env var first
        let enabled = (*env::FNOX_PROMPT_AUTH)
            .or(self.prompt_auth)
            .unwrap_or(true);

        // Only prompt if enabled AND we're in a TTY
        enabled && atty::is(atty::Stream::Stdin)
    }

    /// Get secrets for the default profile (mutable)
    pub fn get_default_secrets_mut(&mut self) -> &mut IndexMap<String, SecretConfig> {
        &mut self.secrets
    }

    /// Get secrets for a specific profile (mutable)
    pub fn get_profile_secrets_mut(
        &mut self,
        profile: &str,
    ) -> &mut IndexMap<String, SecretConfig> {
        &mut self
            .profiles
            .entry(profile.to_string())
            .or_default()
            .secrets
    }

    /// Get effective secrets (default or profile)
    /// For non-default profiles, this merges top-level secrets with profile-specific secrets,
    /// with profile secrets taking precedence.
    ///
    /// Note: If a profile doesn't exist in [profiles], it's treated as "default".
    /// This allows fnox.$FNOX_PROFILE.toml files to work without requiring a [profiles] section.
    pub fn get_secrets(&self, profile: &str) -> Result<IndexMap<String, SecretConfig>> {
        if profile == "default" {
            Ok(self.secrets.clone())
        } else {
            // Start with top-level secrets as base
            let mut secrets = self.secrets.clone();

            // Get profile-specific secrets and merge/override (if profile exists)
            if let Some(profile_config) = self.profiles.get(profile) {
                // Profile-specific secrets override top-level ones
                secrets.extend(profile_config.secrets.clone());
            }
            // If profile doesn't exist in [profiles], that's OK - just use top-level secrets
            // This allows fnox.$FNOX_PROFILE.toml to work without requiring [profiles.xxx]
            Ok(secrets)
        }
    }

    /// Get effective secrets (default or profile, mutable)
    pub fn get_secrets_mut(&mut self, profile: &str) -> &mut IndexMap<String, SecretConfig> {
        if profile == "default" {
            self.get_default_secrets_mut()
        } else {
            self.get_profile_secrets_mut(profile)
        }
    }

    /// Get effective providers for a profile
    pub fn get_providers(&self, profile: &str) -> IndexMap<String, ProviderConfig> {
        let mut providers = self.providers.clone(); // Start with global providers

        if profile != "default"
            && let Some(profile_config) = self.profiles.get(profile)
        {
            providers.extend(profile_config.providers.clone());
        }

        providers
    }

    /// Get the default provider for a profile
    /// Returns the configured default_provider, or auto-selects if there's only one provider
    pub fn get_default_provider(&self, profile: &str) -> Result<Option<String>> {
        let providers = self.get_providers(profile);

        // If no providers configured and this is a root config, return None
        if providers.is_empty() && self.root {
            return Ok(None);
        }

        // If no providers configured, that's an error
        if providers.is_empty() {
            return Err(FnoxError::Config(
                "No providers configured. Add at least one provider to fnox.toml".to_string(),
            ));
        }

        // Check for profile-specific default provider
        if profile != "default"
            && let Some(profile_config) = self.profiles.get(profile)
            && let Some(default_provider_name) = profile_config.default_provider()
        {
            // Validate that the default provider exists
            if !providers.contains_key(default_provider_name) {
                // Try to get source info for better error reporting
                if let Some(source_path) = &profile_config.default_provider_source
                    && let (Some(src), Some(span)) = (
                        source_registry::get_named_source(source_path),
                        profile_config.default_provider_span(),
                    )
                {
                    return Err(FnoxError::DefaultProviderNotFoundWithSource {
                        provider: default_provider_name.to_string(),
                        profile: profile.to_string(),
                        src,
                        span: span.into(),
                    });
                }
                return Err(FnoxError::Config(format!(
                    "Default provider '{}' not found in profile '{}'",
                    default_provider_name, profile
                )));
            }
            return Ok(Some(default_provider_name.to_string()));
        }

        // Check for global default provider (for default profile or as fallback)
        if let Some(default_provider_name) = self.default_provider() {
            // Validate that the default provider exists
            if !providers.contains_key(default_provider_name) {
                // Try to get source info for better error reporting
                if let Some(source_path) = &self.default_provider_source
                    && let (Some(src), Some(span)) = (
                        source_registry::get_named_source(source_path),
                        self.default_provider_span(),
                    )
                {
                    return Err(FnoxError::DefaultProviderNotFoundWithSource {
                        provider: default_provider_name.to_string(),
                        profile: profile.to_string(),
                        src,
                        span: span.into(),
                    });
                }
                return Err(FnoxError::Config(format!(
                    "Default provider '{}' not found in configuration",
                    default_provider_name
                )));
            }
            return Ok(Some(default_provider_name.to_string()));
        }

        // If there's exactly one provider, auto-select it
        if providers.len() == 1 {
            let provider_name = providers.keys().next().unwrap().clone();
            tracing::debug!(
                "Auto-selecting provider '{}' as it's the only one configured",
                provider_name
            );
            return Ok(Some(provider_name));
        }

        // Multiple providers, no default configured
        Ok(None)
    }

    /// Set source paths for all secrets and providers in this config
    fn set_source_paths(&mut self, path: &Path) {
        // Set source paths for default profile secrets
        for (key, secret) in self.secrets.iter_mut() {
            secret.source_path = Some(path.to_path_buf());
            self.secret_sources.insert(key.clone(), path.to_path_buf());
        }

        // Set source paths for default profile providers
        for (provider_name, _) in self.providers.iter() {
            self.provider_sources
                .insert(provider_name.clone(), path.to_path_buf());
        }

        // Set source path for default_provider if set
        if self.default_provider().is_some() {
            self.default_provider_source = Some(path.to_path_buf());
        }

        // Set source paths for named profiles
        for (_profile_name, profile) in self.profiles.iter_mut() {
            for (key, secret) in profile.secrets.iter_mut() {
                secret.source_path = Some(path.to_path_buf());
                profile
                    .secret_sources
                    .insert(key.clone(), path.to_path_buf());
            }

            for (provider_name, _) in profile.providers.iter() {
                profile
                    .provider_sources
                    .insert(provider_name.clone(), path.to_path_buf());
            }

            // Set source path for profile's default_provider if set
            if profile.default_provider().is_some() {
                profile.default_provider_source = Some(path.to_path_buf());
            }
        }
    }

    /// Check if a secret has an empty value that should be flagged as a validation issue.
    /// Returns a ValidationIssue if the secret has an empty value and is not using plain provider.
    fn check_empty_value(
        &self,
        key: &str,
        secret: &SecretConfig,
        profile: &str,
    ) -> Option<crate::error::ValidationIssue> {
        // Early return if value is not an empty string
        let Some(value) = secret.value() else {
            return None; // No value specified - not an issue
        };
        if !value.is_empty() {
            return None; // Non-empty value - not an issue
        }

        // At this point, value is an empty string
        // Allow empty values for plain provider (empty string is a valid secret value)
        if self.is_plain_provider(secret.provider(), profile) {
            return None;
        }
        let message = if profile == "default" {
            format!("Secret '{}' has an empty value", key)
        } else {
            format!(
                "Secret '{}' in profile '{}' has an empty value",
                key, profile
            )
        };
        Some(crate::error::ValidationIssue::with_help(
            message,
            "Set a value for this secret or remove it from the configuration",
        ))
    }

    /// Check if a secret uses the plain provider (where empty values are valid).
    /// Returns true if the provider is "plain" type.
    fn is_plain_provider(&self, secret_provider: Option<&str>, profile: &str) -> bool {
        // Get providers for this profile first (needed for auto-selection)
        let providers = self.get_providers(profile);

        // Determine which provider name to use
        let provider_name = secret_provider
            .map(String::from)
            .or_else(|| {
                // Try profile's default_provider first (only for non-default profiles)
                if profile != "default" {
                    self.profiles
                        .get(profile)
                        .and_then(|p| p.default_provider().map(|s| s.to_string()))
                } else {
                    None
                }
            })
            .or_else(|| self.default_provider().map(|s| s.to_string()))
            .or_else(|| {
                // Auto-select if exactly one provider exists (matching get_default_provider behavior)
                if providers.len() == 1 {
                    providers.keys().next().cloned()
                } else {
                    None
                }
            });

        let Some(provider_name) = provider_name else {
            return false;
        };

        // Look up the provider config
        providers
            .get(&provider_name)
            .is_some_and(|p| p.provider_type() == "plain")
    }

    /// Validate the configuration
    /// Collects all validation issues and returns them together using #[related]
    pub fn validate(&self) -> Result<()> {
        use crate::error::ValidationIssue;

        // If root=true and no providers AND no secrets, that's OK (empty config)
        if self.root
            && self.providers.is_empty()
            && self.profiles.is_empty()
            && self.secrets.is_empty()
        {
            return Ok(());
        }

        let mut issues = Vec::new();

        // Check for secrets with empty values (likely a mistake, but allowed for plain provider)
        for (key, secret) in &self.secrets {
            if let Some(issue) = self.check_empty_value(key, secret, "default") {
                issues.push(issue);
            }
        }

        // Check that there's at least one provider if there are any secrets
        if self.providers.is_empty() && self.profiles.is_empty() && !self.secrets.is_empty() {
            issues.push(ValidationIssue::with_help(
                "No providers configured",
                "Add at least one provider to fnox.toml",
            ));
        }

        // If default_provider is set, validate it exists
        if let Some(default_provider_name) = self.default_provider()
            && !self.providers.contains_key(default_provider_name)
        {
            // Try to get source info for better error reporting
            if let Some(source_path) = &self.default_provider_source
                && let (Some(src), Some(span)) = (
                    source_registry::get_named_source(source_path),
                    self.default_provider_span(),
                )
            {
                return Err(FnoxError::DefaultProviderNotFoundWithSource {
                    provider: default_provider_name.to_string(),
                    profile: "default".to_string(),
                    src,
                    span: span.into(),
                });
            }
            issues.push(ValidationIssue::with_help(
                format!(
                    "Default provider '{}' not found in configuration",
                    default_provider_name
                ),
                format!(
                    "Add [providers.{}] to your config or remove the default_provider setting",
                    default_provider_name
                ),
            ));
        }

        // Validate each profile
        for (profile_name, profile_config) in &self.profiles {
            let providers = self.get_providers(profile_name);

            // Check for profile secrets with empty values (likely a mistake, but allowed for plain provider)
            for (key, secret) in &profile_config.secrets {
                if let Some(issue) = self.check_empty_value(key, secret, profile_name) {
                    issues.push(issue);
                }
            }

            // Each profile must have at least one provider (inherited or its own), unless root=true
            if providers.is_empty() && !self.root {
                issues.push(ValidationIssue::with_help(
                    format!("Profile '{}' has no providers configured", profile_name),
                    format!(
                        "Add [profiles.{}.providers.<name>] or inherit from top-level providers",
                        profile_name
                    ),
                ));
            }

            // If profile has default_provider set, validate it exists
            if let Some(default_provider_name) = profile_config.default_provider()
                && !providers.contains_key(default_provider_name)
            {
                // Try to get source info for better error reporting
                if let Some(source_path) = &profile_config.default_provider_source
                    && let (Some(src), Some(span)) = (
                        source_registry::get_named_source(source_path),
                        profile_config.default_provider_span(),
                    )
                {
                    return Err(FnoxError::DefaultProviderNotFoundWithSource {
                        provider: default_provider_name.to_string(),
                        profile: profile_name.clone(),
                        src,
                        span: span.into(),
                    });
                }
                issues.push(ValidationIssue::with_help(
                    format!(
                        "Default provider '{}' not found in profile '{}'",
                        default_provider_name, profile_name
                    ),
                    format!(
                        "Add [profiles.{}.providers.{}] or remove the default_provider setting",
                        profile_name, default_provider_name
                    ),
                ));
            }
        }

        if issues.is_empty() {
            Ok(())
        } else {
            Err(FnoxError::ConfigValidationFailed { issues })
        }
    }

    /// Get the default provider name, if set.
    pub fn default_provider(&self) -> Option<&str> {
        self.default_provider
            .as_ref()
            .map(|s: &SpannedValue<String>| s.value().as_str())
    }

    /// Get the default provider's source span (byte range in the config file).
    /// Returns None if the default_provider wasn't set or was created programmatically.
    pub fn default_provider_span(&self) -> Option<Range<usize>> {
        self.default_provider
            .as_ref()
            .and_then(|s: &SpannedValue<String>| s.span())
    }

    /// Set the default provider name (without span information).
    pub fn set_default_provider(&mut self, provider: Option<String>) {
        self.default_provider = provider.map(SpannedValue::without_span);
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretConfig {
    /// Create a new secret config with just metadata
    pub fn new() -> Self {
        Self {
            description: None,
            if_missing: None,
            default: None,
            provider: None,
            value: None,
            source_path: None,
        }
    }

    /// Convert this secret config to a TOML inline table for saving
    pub fn to_inline_table(&self) -> toml_edit::InlineTable {
        let mut inline = toml_edit::InlineTable::new();

        if let Some(provider) = self.provider() {
            inline.insert("provider", toml_edit::Value::from(provider));
        }
        if let Some(value) = self.value() {
            inline.insert("value", toml_edit::Value::from(value));
        }
        if let Some(ref description) = self.description {
            inline.insert("description", toml_edit::Value::from(description.as_str()));
        }
        if let Some(ref default) = self.default {
            inline.insert("default", toml_edit::Value::from(default.as_str()));
        }
        if let Some(if_missing) = self.if_missing {
            let if_missing_str = match if_missing {
                IfMissing::Error => "error",
                IfMissing::Warn => "warn",
                IfMissing::Ignore => "ignore",
            };
            inline.insert("if_missing", toml_edit::Value::from(if_missing_str));
        }

        inline.fmt();
        inline
    }

    /// Check if this secret has any value (provider, value, or default)
    pub fn has_value(&self) -> bool {
        self.provider().is_some() || self.value().is_some() || self.default.is_some()
    }

    /// Get the provider name, if set.
    pub fn provider(&self) -> Option<&str> {
        self.provider.as_ref().map(|s| s.value().as_str())
    }

    /// Get the provider's source span (byte range in the config file).
    /// Returns None if the provider wasn't set or was created programmatically.
    pub fn provider_span(&self) -> Option<Range<usize>> {
        self.provider.as_ref().and_then(|s| s.span())
    }

    /// Set the provider name (without span information).
    pub fn set_provider(&mut self, provider: Option<String>) {
        self.provider = provider.map(SpannedValue::without_span);
    }

    /// Get the value, if set.
    pub fn value(&self) -> Option<&str> {
        self.value
            .as_ref()
            .map(|s: &SpannedValue<String>| s.value().as_str())
    }

    /// Set the value (without span information).
    pub fn set_value(&mut self, value: Option<String>) {
        self.value = value.map(SpannedValue::without_span);
    }
}

impl ProfileConfig {
    /// Create a new profile config
    pub fn new() -> Self {
        Self {
            providers: IndexMap::new(),
            default_provider: None,
            secrets: IndexMap::new(),
            provider_sources: HashMap::new(),
            secret_sources: HashMap::new(),
            default_provider_source: None,
        }
    }

    /// Check if the profile is effectively empty (no serializable content)
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty() && self.secrets.is_empty() && self.default_provider().is_none()
    }

    /// Get the default provider name, if set.
    pub fn default_provider(&self) -> Option<&str> {
        self.default_provider
            .as_ref()
            .map(|s: &SpannedValue<String>| s.value().as_str())
    }

    /// Get the default provider's source span (byte range in the config file).
    /// Returns None if the default_provider wasn't set or was created programmatically.
    pub fn default_provider_span(&self) -> Option<Range<usize>> {
        self.default_provider
            .as_ref()
            .and_then(|s: &SpannedValue<String>| s.span())
    }
}

impl Default for SecretConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_import_not_serialized() {
        let config = Config::new();
        let toml = toml_edit::ser::to_string_pretty(&config).unwrap();
        assert!(
            !toml.contains("import"),
            "Empty import should not be serialized"
        );
    }

    #[test]
    fn test_non_empty_import_is_serialized() {
        let mut config = Config::new();
        config.import.push("other.toml".to_string());
        let toml = toml_edit::ser::to_string_pretty(&config).unwrap();
        assert!(
            toml.contains("import"),
            "Non-empty import should be serialized"
        );
        assert!(
            toml.contains("other.toml"),
            "Import value should be present"
        );
    }

    #[test]
    fn test_empty_profiles_not_serialized() {
        let config = Config::new();
        let toml = toml_edit::ser::to_string_pretty(&config).unwrap();
        assert!(
            !toml.contains("profiles"),
            "Empty profiles should not be serialized"
        );
    }

    #[test]
    fn test_non_empty_profiles_is_serialized() {
        let mut config = Config::new();

        // Add a provider and secret to the prod profile
        let mut prod_profile = ProfileConfig::new();
        prod_profile
            .providers
            .insert("plain".to_string(), ProviderConfig::Plain);
        let mut secret = SecretConfig::new();
        secret.set_value(Some("test-value".to_string()));
        prod_profile
            .secrets
            .insert("TEST_SECRET".to_string(), secret);

        config.profiles.insert("prod".to_string(), prod_profile);
        let toml = toml_edit::ser::to_string_pretty(&config).unwrap();

        // Print the TOML for debugging
        eprintln!("Generated TOML:\n{}", toml);

        assert!(
            toml.contains("profiles"),
            "Non-empty profiles should be serialized"
        );
        assert!(toml.contains("prod"), "Profile name should be present");

        // Check that we don't have a standalone [profiles] header
        // We should only have [profiles.prod] style headers
        assert!(
            !toml.contains("[profiles]\n"),
            "Should not have standalone [profiles] header"
        );
    }

    #[test]
    fn test_empty_profile_not_serialized() {
        use std::io::Read;

        let mut config = Config::new();
        // Add an empty profile (no providers, no secrets)
        config
            .profiles
            .insert("prod".to_string(), ProfileConfig::new());

        // Use save() which cleans up empty profiles
        let temp_file = std::env::temp_dir().join("fnox_test_empty_profile.toml");
        config.save(&temp_file).unwrap();

        let mut toml = String::new();
        std::fs::File::open(&temp_file)
            .unwrap()
            .read_to_string(&mut toml)
            .unwrap();
        std::fs::remove_file(&temp_file).ok();

        eprintln!("Generated TOML with empty profile:\n{}", toml);

        // Empty profiles should not appear in the output at all
        // Because save() cleans them up
        assert!(
            !toml.contains("[profiles"),
            "Empty profile should not be serialized"
        );
        assert!(
            !toml.contains("prod"),
            "Empty profile name should not appear"
        );
    }
}
