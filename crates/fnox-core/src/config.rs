use crate::env;
use crate::error::{FnoxError, Result};
use crate::settings::Settings;
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

/// Default config filename, used as the clap default for `--config`.
pub const DEFAULT_CONFIG_FILENAME: &str = "fnox.toml";

/// Returns all config filenames in load order (first = lowest priority, last = highest priority).
///
/// Order: main configs → profile configs (in the order given) → local configs
/// Within each group, non-dotfiles come first (lower priority); dotfiles follow (higher priority).
pub fn all_config_filenames(profiles: &[String]) -> Vec<String> {
    let mut files = vec![
        DEFAULT_CONFIG_FILENAME.to_string(),
        ".fnox.toml".to_string(),
    ];
    for p in profiles.iter().filter(|p| *p != "default") {
        files.push(format!("fnox.{p}.toml"));
        files.push(format!(".fnox.{p}.toml"));
    }
    files.push("fnox.local.toml".to_string());
    files.push(".fnox.local.toml".to_string());
    files
}

/// Returns the local override filename for a supported config basename.
///
/// Only `fnox.toml` and `.fnox.toml` have corresponding local override files.
pub fn local_override_filename(path: &Path) -> Option<&'static str> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("fnox.toml") => Some("fnox.local.toml"),
        Some(".fnox.toml") => Some(".fnox.local.toml"),
        _ => None,
    }
}

/// Find the most appropriate existing config file in `dir` for writing.
///
/// When non-default profiles are active, the last profile is the write target. Its
/// profile-specific file (e.g. `fnox.staging.toml`) is preferred if it exists, so
/// secrets stay scoped to that profile. Otherwise falls back to the lowest-priority
/// existing file. If no config files exist yet, returns `fnox.toml`.
pub fn find_local_config(dir: &Path, profiles: &[String]) -> PathBuf {
    // The last profile is the write target.
    let write_profile = Config::write_profile(profiles);

    // If the write profile is non-default, prefer its config file first
    if write_profile != "default" {
        for name in [
            format!("fnox.{write_profile}.toml"),
            format!(".fnox.{write_profile}.toml"),
        ] {
            let path = dir.join(&name);
            if path.exists() {
                return path;
            }
        }
    }

    // Fall back to lowest-priority existing base file.
    // When a non-default profile is active, exclude local files
    // (fnox.local.toml, .fnox.local.toml) to avoid silently routing profile-scoped
    // secrets into a gitignored local-override file.
    let is_profiled = profiles.iter().any(|p| p != "default");
    for name in &["fnox.toml", ".fnox.toml"] {
        let path = dir.join(name);
        if path.exists() {
            return path;
        }
    }
    if !is_profiled {
        for name in &["fnox.local.toml", ".fnox.local.toml"] {
            let path = dir.join(name);
            if path.exists() {
                return path;
            }
        }
    }
    dir.join(DEFAULT_CONFIG_FILENAME)
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

    /// Lease backend configurations (for default profile)
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub leases: IndexMap<String, crate::lease_backends::LeaseBackendConfig>,

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

    /// Default env injection mode for all secrets in this config.
    /// Set `env = "exec"` to keep every secret out of the interactive shell
    /// (secrets are still injected into `fnox exec` subprocesses) unless a
    /// secret explicitly opts back in with `env = true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvMode>,

    /// Whether to prompt for authentication when provider auth fails (default: true in TTY)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_auth: Option<bool>,

    /// MCP server configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpConfig>,

    /// Per-user daemon configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon: Option<DaemonConfig>,

    /// Track which config file each provider came from (not serialized)
    #[serde(skip)]
    pub provider_sources: HashMap<String, PathBuf>,

    /// Track which config file each secret came from (not serialized)
    #[serde(skip)]
    pub secret_sources: HashMap<String, PathBuf>,

    /// Track which config file the default_provider came from (not serialized)
    #[serde(skip)]
    pub default_provider_source: Option<PathBuf>,

    /// The project root directory — the nearest directory to cwd that contains
    /// a config file. Used for scoping the lease ledger per-project.
    #[serde(skip)]
    pub project_dir: Option<PathBuf>,
}

/// Cached sync data for a secret (provider + encrypted value)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SyncConfig {
    pub provider: String,
    pub value: String,
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

    /// Where to inject this secret as an environment variable:
    /// - `true` — shell integration and `fnox exec` (default)
    /// - `"exec"` — only `fnox exec` subprocesses, never the interactive shell
    /// - `false` — never injected; only accessible via `fnox get`
    ///
    /// When unset, inherits the top-level `env` default (which itself defaults to `true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvMode>,

    /// Write secret to a temporary file and set env var to the file path instead of the secret value
    #[serde(default, skip_serializing_if = "is_false")]
    pub as_file: bool,
    /// JSON path to extract from the secret value (supports dot notation: "nested.key")
    /// When set, the secret value is parsed as JSON and the specified path is extracted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_path: Option<String>,

    /// 1-indexed line number to extract from the secret value.
    /// When set, the secret value is split on newlines and the Nth line is returned.
    /// Useful for providers whose entries pack multiple related values into a
    /// single secret (e.g. one value per line). Mutually exclusive with `json_path`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub line: Option<usize>,

    /// Cached sync data (provider + encrypted value from `fnox sync`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncConfig>,

    /// Path to the config file where this secret was defined (not serialized)
    #[serde(skip)]
    pub source_path: Option<PathBuf>,

    /// Whether this secret was loaded from a [profiles.X.secrets] section (not serialized).
    /// When false, the secret was loaded from a root-level [secrets] section.
    #[serde(skip)]
    pub source_is_profile: bool,

    /// The profile name this secret was loaded from, if any (not serialized).
    #[serde(skip)]
    pub source_profile: Option<String>,

    /// Whether this secret may be cached by the per-user daemon.
    /// Defaults to true; set false for secrets that should always resolve directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_cache: Option<bool>,
}

/// Configuration for a profile
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// Lease backend configurations for this profile
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub leases: IndexMap<String, crate::lease_backends::LeaseBackendConfig>,

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

/// Available MCP tools
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpTool {
    GetSecret,
    Exec,
}

impl McpTool {
    /// Returns the tool name as it appears in MCP protocol
    pub fn tool_name(&self) -> &'static str {
        match self {
            McpTool::GetSecret => "get_secret",
            McpTool::Exec => "exec",
        }
    }
}

/// MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct McpConfig {
    /// Which MCP tools to expose (default: ["get_secret", "exec"])
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tools")]
    tools_raw: Option<Vec<McpTool>>,

    /// Timeout in seconds for exec tool subprocess (default: 300, minimum: 1)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub exec_timeout_secs: Option<u64>,

    /// Whether to redact secret values from exec tool output (default: true).
    /// When enabled, resolved secret values are replaced with [REDACTED] in
    /// stdout/stderr before returning to the agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redact_output: Option<bool>,

    /// Optional allowlist of secret names visible to the MCP server.
    /// When set, only these secrets are resolved and available via get_secret/exec.
    /// When None, all profile secrets are available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
}

/// Per-user daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct DaemonConfig {
    /// Enable daemon-backed resolution for supported read commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Idle timeout before the daemon exits, such as "8h", "30m", or "300s".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,
}

impl DaemonConfig {
    pub const DEFAULT_IDLE_TIMEOUT: &'static str = "8h";

    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    pub fn idle_timeout(&self) -> &str {
        self.idle_timeout
            .as_deref()
            .unwrap_or(Self::DEFAULT_IDLE_TIMEOUT)
    }
}

impl McpConfig {
    fn default_tools() -> Vec<McpTool> {
        vec![McpTool::GetSecret, McpTool::Exec]
    }

    /// Whether `tools` was explicitly set in the config file
    pub fn tools_explicitly_set(&self) -> bool {
        self.tools_raw.is_some()
    }

    /// Returns the effective tools list (default if not explicitly set)
    pub fn tools(&self) -> Vec<McpTool> {
        self.tools_raw.clone().unwrap_or_else(Self::default_tools)
    }

    /// Set the tools list explicitly
    pub fn set_tools(&mut self, tools: Vec<McpTool>) {
        self.tools_raw = Some(tools);
    }

    /// Whether exec output redaction is enabled (default: true)
    pub fn redact_output(&self) -> bool {
        self.redact_output.unwrap_or(true)
    }

    /// Filter a secrets map to only include allowed secrets.
    /// Returns the map unchanged if no allowlist is set.
    pub fn filter_secrets(
        &self,
        secrets: IndexMap<String, SecretConfig>,
    ) -> IndexMap<String, SecretConfig> {
        match &self.secrets {
            None => secrets,
            Some(allowlist) => {
                let allowed: std::collections::HashSet<&str> =
                    allowlist.iter().map(|s| s.as_str()).collect();
                secrets
                    .into_iter()
                    .filter(|(k, _)| allowed.contains(k.as_str()))
                    .collect()
            }
        }
    }
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

/// Controls where a secret's value is injected as an environment variable.
///
/// Serialized in TOML as `true` (Shell), `"exec"` (Exec), or `false` (Never).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EnvMode {
    /// Injected by shell integration (hook-env) and `fnox exec` (TOML: `true`)
    #[default]
    Shell,
    /// Only injected into `fnox exec` subprocesses, never the interactive shell (TOML: `"exec"`)
    Exec,
    /// Never injected as an env var; only accessible via `fnox get` (TOML: `false`)
    Never,
}

impl EnvMode {
    /// Whether shell integration (hook-env / export) should inject this secret
    pub fn in_shell(self) -> bool {
        matches!(self, Self::Shell)
    }

    /// Whether `fnox exec` subprocesses should receive this secret
    pub fn in_exec(self) -> bool {
        matches!(self, Self::Shell | Self::Exec)
    }

    /// TOML representation for config-file editing
    pub fn to_toml_value(self) -> toml_edit::Value {
        match self {
            Self::Shell => toml_edit::Value::from(true),
            Self::Exec => toml_edit::Value::from("exec"),
            Self::Never => toml_edit::Value::from(false),
        }
    }
}

impl Serialize for EnvMode {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Shell => serializer.serialize_bool(true),
            Self::Exec => serializer.serialize_str("exec"),
            Self::Never => serializer.serialize_bool(false),
        }
    }
}

impl<'de> Deserialize<'de> for EnvMode {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct EnvModeVisitor;

        impl serde::de::Visitor<'_> for EnvModeVisitor {
            type Value = EnvMode;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("true, false, or \"exec\"")
            }

            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<EnvMode, E> {
                Ok(if v { EnvMode::Shell } else { EnvMode::Never })
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<EnvMode, E> {
                match v {
                    "exec" => Ok(EnvMode::Exec),
                    other => Err(E::invalid_value(
                        serde::de::Unexpected::Str(other),
                        &"true, false, or \"exec\"",
                    )),
                }
            }
        }

        deserializer.deserialize_any(EnvModeVisitor)
    }
}

impl JsonSchema for EnvMode {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EnvMode".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "Where to inject the secret as an env var: true = shell + fnox exec (default), \"exec\" = fnox exec subprocesses only, false = never (fnox get only)",
            "anyOf": [
                { "type": "boolean" },
                { "type": "string", "enum": ["exec"] }
            ]
        })
    }
}

impl Config {
    /// Load configuration using the appropriate strategy
    pub fn load_smart<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();

        // If the path is one of the default config filenames, use recursive loading
        let default_filenames = all_config_filenames(&[]);
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
            Ok((mut config, _)) => {
                // Find the nearest directory to cwd that contains a config file.
                // This is the project root used for scoping the lease ledger.
                config.project_dir = Self::find_project_dir(&current_dir);
                Ok(config)
            }
            Err(e) => Err(e),
        }
    }

    /// Recursively search for fnox.toml files and merge them
    /// Returns (config, found_any) where found_any indicates if any config file was found
    fn load_recursive(dir: &Path, found_any: bool) -> Result<(Self, bool)> {
        // Get active profiles from Settings (respects: CLI flag > Env var > Default)
        let profiles = Self::get_profiles(&[]);
        let filenames = all_config_filenames(&profiles);

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

    /// Find the nearest directory to `start` that contains a config file.
    /// Walks upward from `start` and returns the first match.
    fn find_project_dir(start: &Path) -> Option<PathBuf> {
        let profiles = Self::get_profiles(&[]);
        let filenames = all_config_filenames(&profiles);
        let mut dir = Some(start);
        while let Some(d) = dir {
            for filename in &filenames {
                if d.join(filename).exists() {
                    return Some(d.to_path_buf());
                }
            }
            dir = d.parent();
        }
        None
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
        let absolute_path =
            crate::config_path::resolve_relative_to_dir(import_path, Some(base_dir));

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

        // Merge env default (overlay takes precedence)
        if overlay.env.is_some() {
            merged.env = overlay.env;
        }

        // Merge prompt_auth (overlay takes precedence)
        if overlay.prompt_auth.is_some() {
            merged.prompt_auth = overlay.prompt_auth;
        }

        // Merge mcp (overlay takes precedence, field-by-field to avoid
        // silently re-enabling tools when overlay only sets exec_timeout_secs)
        if let Some(overlay_mcp) = overlay.mcp {
            let base_mcp = merged.mcp.get_or_insert_with(McpConfig::default);
            if overlay_mcp.tools_explicitly_set() {
                base_mcp.set_tools(overlay_mcp.tools());
            }
            if overlay_mcp.exec_timeout_secs.is_some() {
                base_mcp.exec_timeout_secs = overlay_mcp.exec_timeout_secs;
            }
            if overlay_mcp.redact_output.is_some() {
                base_mcp.redact_output = overlay_mcp.redact_output;
            }
            // Replace entirely — a partial overlay should not silently
            // re-expose secrets that the base config restricted.
            if overlay_mcp.secrets.is_some() {
                base_mcp.secrets = overlay_mcp.secrets;
            }
        }

        // Merge daemon (overlay takes precedence, field-by-field)
        if let Some(overlay_daemon) = overlay.daemon {
            let base_daemon = merged.daemon.get_or_insert_with(DaemonConfig::default);
            if overlay_daemon.enabled.is_some() {
                base_daemon.enabled = overlay_daemon.enabled;
            }
            if overlay_daemon.idle_timeout.is_some() {
                base_daemon.idle_timeout = overlay_daemon.idle_timeout;
            }
        }

        // Merge default_provider and its source (overlay takes precedence)
        if overlay.default_provider.is_some() {
            merged.default_provider = overlay.default_provider;
            merged.default_provider_source = overlay.default_provider_source;
        }

        // Merge lease backends (overlay takes precedence)
        for (name, lease) in overlay.leases {
            merged.leases.insert(name, lease);
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
                for (lease_name, lease) in profile.leases {
                    existing_profile.leases.insert(lease_name, lease);
                }
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
            content.parse::<DocumentMut>().map_err(|e| {
                FnoxError::Config(format!(
                    "Failed to parse TOML in {}: {}",
                    target_file.display(),
                    e
                ))
            })?
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

        if let Some(item) = secrets_table.get_mut(secret_name) {
            secret_config.update_toml_item(item);
            if let Some(mut key) = secrets_table.key_mut(secret_name) {
                key.leaf_decor_mut().set_suffix("");
            }
        } else {
            secrets_table[secret_name] =
                Item::Value(Value::InlineTable(secret_config.to_inline_table()));

            // Remove trailing space from key to match format: KEY= { ... } instead of KEY = { ... }
            if let Some(mut key) = secrets_table.key_mut(secret_name) {
                key.leaf_decor_mut().set_suffix("");
            }
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

    /// Remove a single secret from a config file, preserving comments and formatting.
    ///
    /// This method directly manipulates the TOML document AST rather than
    /// re-serializing, so all comments, whitespace, and formatting are preserved.
    pub fn remove_secret_from_source(
        secret_name: &str,
        profile: &str,
        target_file: &Path,
    ) -> Result<bool> {
        use toml_edit::DocumentMut;

        let content =
            fs::read_to_string(target_file).map_err(|source| FnoxError::ConfigReadFailed {
                path: target_file.to_path_buf(),
                source,
            })?;
        let mut doc = content.parse::<DocumentMut>().map_err(|e| {
            FnoxError::Config(format!(
                "Failed to parse TOML in {}: {}",
                target_file.display(),
                e
            ))
        })?;

        // Navigate to the secrets table
        let removed = if profile == "default" {
            doc.get_mut("secrets")
                .and_then(|s| s.as_table_mut())
                .map(|t| t.remove(secret_name).is_some())
                .unwrap_or(false)
        } else {
            doc.get_mut("profiles")
                .and_then(|p| p.as_table_mut())
                .and_then(|p| p.get_mut(profile))
                .and_then(|p| p.as_table_mut())
                .and_then(|p| p.get_mut("secrets"))
                .and_then(|s| s.as_table_mut())
                .map(|t| t.remove(secret_name).is_some())
                .unwrap_or(false)
        };

        if removed {
            fs::write(target_file, doc.to_string()).map_err(|source| {
                FnoxError::ConfigWriteFailed {
                    path: target_file.to_path_buf(),
                    source,
                }
            })?;
        }

        Ok(removed)
    }

    /// Save multiple secrets to a config file, preserving comments and formatting.
    ///
    /// This is the batch equivalent of `save_secret_to_source`, used by `fnox import`.
    pub fn save_secrets_to_source(
        secrets: &IndexMap<String, SecretConfig>,
        profile: &str,
        target_file: &Path,
    ) -> Result<()> {
        use toml_edit::{DocumentMut, Item, Value};

        // Load existing document or create new one (preserves comments)
        let mut doc = if target_file.exists() {
            let content =
                fs::read_to_string(target_file).map_err(|source| FnoxError::ConfigReadFailed {
                    path: target_file.to_path_buf(),
                    source,
                })?;
            content.parse::<DocumentMut>().map_err(|e| {
                FnoxError::Config(format!(
                    "Failed to parse TOML in {}: {}",
                    target_file.display(),
                    e
                ))
            })?
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

        // Insert/update each secret, preserving existing inline-vs-table style.
        for (name, config) in secrets {
            let name_str = name.as_str();

            // Update existing values in-place to preserve decor/comments on the entry
            if let Some(item) = secrets_table.get_mut(name_str) {
                config.update_toml_item(item);
                if let Some(mut key) = secrets_table.key_mut(name_str) {
                    key.leaf_decor_mut().set_suffix("");
                }
            } else {
                secrets_table[name_str] = Item::Value(Value::InlineTable(config.to_inline_table()));

                if let Some(mut key) = secrets_table.key_mut(name_str) {
                    key.leaf_decor_mut().set_suffix("");
                }
            }
        }

        // Write back (preserves all comments and formatting)
        fs::write(target_file, doc.to_string()).map_err(|source| FnoxError::ConfigWriteFailed {
            path: target_file.to_path_buf(),
            source,
        })?;

        Ok(())
    }

    /// Create a new default configuration
    pub fn new() -> Self {
        Self {
            import: Vec::new(),
            root: false,
            leases: IndexMap::new(),
            providers: IndexMap::new(),
            default_provider: None,
            secrets: IndexMap::new(),
            profiles: IndexMap::new(),
            age_key_file: None,
            if_missing: None,
            env: None,
            prompt_auth: None,
            mcp: None,
            daemon: None,
            provider_sources: HashMap::new(),
            secret_sources: HashMap::new(),
            default_provider_source: None,
            project_dir: None,
        }
    }

    /// Resolve the ordered list of active profiles.
    ///
    /// Precedence: CLI flags > FNOX_PROFILE env > settings default. If all are
    /// empty, returns `["default"]`. The `default` profile name represents the
    /// top-level config; no `[profiles.default]` lookup is performed.
    pub fn get_profiles(cli_profiles: &[String]) -> Vec<String> {
        if !cli_profiles.is_empty() {
            return Self::normalize_profiles(cli_profiles);
        }
        Self::normalize_profiles(&Settings::get().profile)
    }

    /// Normalize a profile list: split comma-separated entries, trim whitespace,
    /// drop invalid names, and remove empty entries. Order is preserved.
    pub fn normalize_profiles(input: &[String]) -> Vec<String> {
        let profiles: Vec<String> = input
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && env::is_valid_profile_name(s))
            .collect();
        if profiles.is_empty() {
            vec!["default".to_string()]
        } else {
            profiles
        }
    }

    /// Format a profile list for display.
    pub fn display_profiles(profiles: &[String]) -> String {
        if profiles.is_empty() {
            "default".to_string()
        } else {
            profiles.join(",")
        }
    }

    /// Return the profile that write operations should target.
    pub fn write_profile(profiles: &[String]) -> &str {
        profiles.last().map(String::as_str).unwrap_or("default")
    }

    /// Determine if we should prompt for authentication when provider auth fails.
    /// Priority: env var > config > default (true)
    /// Returns true only if prompting is enabled AND we're in a TTY.
    pub fn should_prompt_auth(&self) -> bool {
        // Check env var first
        let enabled = (*env::FNOX_PROMPT_AUTH)
            .or(self.prompt_auth)
            .unwrap_or(true);

        // Only prompt if enabled, not explicitly non-interactive, and we're in a TTY
        enabled && !env::is_non_interactive() && atty::is(atty::Stream::Stdin)
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

    /// Get effective secrets for the active profile stack.
    ///
    /// Top-level secrets form the base (unless `no_defaults` is set and at least one
    /// non-default profile is active). Profile-specific secrets are overlaid in order,
    /// with later profiles taking precedence.
    pub fn get_secrets(&self, profiles: &[String]) -> Result<IndexMap<String, SecretConfig>> {
        self.get_secrets_with_no_defaults(profiles, Settings::get().no_defaults)
    }

    /// Get effective secrets with an explicit no-defaults setting.
    pub fn get_secrets_with_no_defaults(
        &self,
        profiles: &[String],
        no_defaults: bool,
    ) -> Result<IndexMap<String, SecretConfig>> {
        let has_non_default = profiles.iter().any(|p| p != "default");
        let mut secrets = if !has_non_default || !no_defaults {
            self.secrets.clone()
        } else {
            IndexMap::new()
        };

        for profile in profiles.iter().filter(|p| *p != "default") {
            if let Some(profile_config) = self.profiles.get(profile) {
                secrets.extend(profile_config.secrets.clone());
            }
        }

        // Secrets that don't set `env` themselves inherit the top-level default
        if self.env.is_some() {
            for secret in secrets.values_mut() {
                if secret.env.is_none() {
                    secret.env = self.env;
                }
            }
        }

        Ok(secrets)
    }

    /// Look up a single secret by key without cloning the secrets map.
    ///
    /// Mirrors the precedence used by [`Self::get_secrets`]: later profiles take
    /// precedence, falling back to top-level secrets unless `no_defaults` is set
    /// and at least one non-default profile is active.
    pub fn get_secret(&self, profiles: &[String], key: &str) -> Option<&SecretConfig> {
        self.get_secret_with_no_defaults(profiles, key, Settings::get().no_defaults)
    }

    /// Look up a single secret with an explicit no-defaults setting.
    pub fn get_secret_with_no_defaults(
        &self,
        profiles: &[String],
        key: &str,
        no_defaults: bool,
    ) -> Option<&SecretConfig> {
        let has_non_default = profiles.iter().any(|p| p != "default");

        for profile in profiles.iter().filter(|p| *p != "default").rev() {
            if let Some(profile_config) = self.profiles.get(profile)
                && let Some(secret) = profile_config.secrets.get(key)
            {
                return Some(secret);
            }
        }

        if has_non_default && no_defaults {
            return None;
        }

        self.secrets.get(key)
    }

    /// Get effective secrets (mutable) for the write target profile.
    ///
    /// The write target is the last active profile. If it is `default` (or the
    /// list is empty), the top-level secrets map is returned.
    pub fn get_secrets_mut(&mut self, profiles: &[String]) -> &mut IndexMap<String, SecretConfig> {
        let write_profile = Self::write_profile(profiles);
        if write_profile == "default" {
            self.get_default_secrets_mut()
        } else {
            self.get_profile_secrets_mut(write_profile)
        }
    }

    /// Get effective lease backends for the active profile stack.
    ///
    /// Top-level leases form the base. Profile-specific leases are overlaid in
    /// order, with later profiles taking precedence.
    pub fn get_leases(
        &self,
        profiles: &[String],
    ) -> IndexMap<String, crate::lease_backends::LeaseBackendConfig> {
        let mut leases = self.leases.clone();

        for profile in profiles.iter().filter(|p| *p != "default") {
            if let Some(profile_config) = self.profiles.get(profile) {
                leases.extend(profile_config.leases.clone());
            }
        }

        leases
    }

    /// Get effective providers for the active profile stack.
    ///
    /// Top-level providers form the base. Profile-specific providers are overlaid
    /// in order, with later profiles taking precedence.
    pub fn get_providers(&self, profiles: &[String]) -> IndexMap<String, ProviderConfig> {
        let mut providers = self.providers.clone();

        for profile in profiles.iter().filter(|p| *p != "default") {
            if let Some(profile_config) = self.profiles.get(profile) {
                providers.extend(profile_config.providers.clone());
            }
        }

        providers
    }

    /// Get the default provider for the active profile stack.
    ///
    /// Returns the configured default_provider (last profile that sets one wins),
    /// or auto-selects if there's only one provider. Top-level default_provider
    /// is used when no profile overrides it.
    pub fn get_default_provider(&self, profiles: &[String]) -> Result<Option<String>> {
        let providers = self.get_providers(profiles);

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

        // Find the winning default_provider: last profile that sets one wins.
        let mut winning_profile = None;
        let mut default_provider_name: Option<&str> = None;
        if let Some(name) = self.default_provider() {
            winning_profile = Some("default");
            default_provider_name = Some(name);
        }
        for profile in profiles.iter().filter(|p| *p != "default") {
            if let Some(profile_config) = self.profiles.get(profile)
                && let Some(name) = profile_config.default_provider()
            {
                winning_profile = Some(profile.as_str());
                default_provider_name = Some(name);
            }
        }

        if let Some(name) = default_provider_name {
            // Validate that the default provider exists
            if !providers.contains_key(name) {
                let profile = winning_profile.unwrap_or("default");
                if let Some(source_path) = self.default_provider_source_for(profile) {
                    let span = self.default_provider_span_for(profile);
                    if let (Some(src), Some(span)) =
                        (source_registry::get_named_source(&source_path), span)
                    {
                        return Err(FnoxError::DefaultProviderNotFoundWithSource {
                            provider: name.to_string(),
                            profile: profile.to_string(),
                            src,
                            span: span.into(),
                        });
                    }
                }
                if profile == "default" {
                    return Err(FnoxError::Config(format!(
                        "Default provider '{}' not found in configuration",
                        name
                    )));
                }
                return Err(FnoxError::Config(format!(
                    "Default provider '{}' not found in profile '{}'",
                    name, profile
                )));
            }
            return Ok(Some(name.to_string()));
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

    /// Source path for the effective default_provider of a given profile name.
    fn default_provider_source_for(&self, profile: &str) -> Option<PathBuf> {
        if profile == "default" {
            self.default_provider_source.clone()
        } else {
            self.profiles
                .get(profile)
                .and_then(|p| p.default_provider_source.clone())
        }
    }

    /// Source span for the effective default_provider of a given profile name.
    fn default_provider_span_for(&self, profile: &str) -> Option<Range<usize>> {
        if profile == "default" {
            self.default_provider_span()
        } else {
            self.profiles
                .get(profile)
                .and_then(|p| p.default_provider_span())
        }
    }

    /// Set source paths for all secrets and providers in this config
    fn set_source_paths(&mut self, path: &Path) {
        // Set source paths for default profile secrets
        for (key, secret) in self.secrets.iter_mut() {
            secret.source_path = Some(path.to_path_buf());
            secret.source_is_profile = false;
            secret.source_profile = None;
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
        for (profile_name, profile) in self.profiles.iter_mut() {
            for (key, secret) in profile.secrets.iter_mut() {
                secret.source_path = Some(path.to_path_buf());
                secret.source_is_profile = true;
                secret.source_profile = Some(profile_name.clone());
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
        let providers = self.get_providers(&[profile.to_string()]);

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
            let providers = self.get_providers(&[profile_name.to_string()]);

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
            env: None,
            as_file: false,
            json_path: None,
            line: None,
            sync: None,
            source_path: None,
            source_is_profile: false,
            source_profile: None,
            daemon_cache: None,
        }
    }

    /// Effective env injection mode for this secret.
    ///
    /// Note: [`Config::get_secrets`] stamps the top-level `env` default into
    /// secrets that don't set it, so on maps obtained from `get_secrets` this
    /// is the fully-resolved mode. On a raw `SecretConfig` an unset `env`
    /// falls back to [`EnvMode::Shell`].
    pub fn env_mode(&self) -> EnvMode {
        self.env.unwrap_or_default()
    }

    /// Return a copy that will resolve to the original provider value,
    /// skipping post-processing and cached sync values.
    pub fn for_raw_resolve(&self) -> Self {
        let mut config = self.clone();
        config.json_path = None;
        config.line = None;
        config.sync = None;
        config.default = None;
        config
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
        if let Some(ref json_path) = self.json_path {
            inline.insert("json_path", toml_edit::Value::from(json_path.as_str()));
        }
        if let Some(line) = self.line {
            inline.insert("line", toml_edit::Value::from(line as i64));
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
        if let Some(env) = self.env {
            inline.insert("env", env.to_toml_value());
        }
        if self.as_file {
            inline.insert("as_file", toml_edit::Value::from(true));
        }
        if let Some(ref sync) = self.sync {
            let mut sync_table = toml_edit::InlineTable::new();
            sync_table.insert("provider", toml_edit::Value::from(sync.provider.as_str()));
            sync_table.insert("value", toml_edit::Value::from(sync.value.as_str()));
            sync_table.fmt();
            inline.insert("sync", toml_edit::Value::InlineTable(sync_table));
        }
        if let Some(daemon_cache) = self.daemon_cache {
            inline.insert("daemon_cache", toml_edit::Value::from(daemon_cache));
        }

        inline.fmt();
        inline
    }

    /// Write this secret config into an existing TOML table while preserving
    /// that table's header/decor and table-style representation.
    pub fn write_to_table(&self, table: &mut toml_edit::Table) {
        use toml_edit::{Item, Value};

        fn set_or_remove(table: &mut toml_edit::Table, key: &str, value: Option<Value>) {
            if let Some(value) = value {
                table[key] = Item::Value(value);
            } else {
                table.remove(key);
            }
        }

        set_or_remove(table, "provider", self.provider().map(Value::from));
        set_or_remove(table, "value", self.value().map(Value::from));
        set_or_remove(
            table,
            "json_path",
            self.json_path.as_deref().map(Value::from),
        );
        set_or_remove(
            table,
            "line",
            self.line.map(|line| Value::from(line as i64)),
        );
        set_or_remove(
            table,
            "description",
            self.description.as_deref().map(Value::from),
        );
        set_or_remove(table, "default", self.default.as_deref().map(Value::from));
        set_or_remove(
            table,
            "if_missing",
            self.if_missing.map(|if_missing| {
                Value::from(match if_missing {
                    IfMissing::Error => "error",
                    IfMissing::Warn => "warn",
                    IfMissing::Ignore => "ignore",
                })
            }),
        );
        set_or_remove(table, "env", self.env.map(EnvMode::to_toml_value));
        set_or_remove(table, "as_file", self.as_file.then(|| Value::from(true)));
        set_or_remove(
            table,
            "sync",
            self.sync.as_ref().map(|sync| {
                let mut sync_table = toml_edit::InlineTable::new();
                sync_table.insert("provider", Value::from(sync.provider.as_str()));
                sync_table.insert("value", Value::from(sync.value.as_str()));
                sync_table.fmt();
                Value::InlineTable(sync_table)
            }),
        );
        set_or_remove(table, "daemon_cache", self.daemon_cache.map(Value::from));
    }

    /// Update a TOML item with this secret config while preserving the
    /// item's existing table-vs-inline-table style.
    pub fn update_toml_item(&self, item: &mut toml_edit::Item) {
        use toml_edit::{Item, Value};

        match item {
            Item::Table(table) => self.write_to_table(table),
            Item::Value(Value::InlineTable(existing_inline)) => {
                *existing_inline = self.to_inline_table();
            }
            _ => {
                *item = Item::Value(Value::InlineTable(self.to_inline_table()));
            }
        }
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
            leases: IndexMap::new(),
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
        self.leases.is_empty()
            && self.providers.is_empty()
            && self.secrets.is_empty()
            && self.default_provider().is_none()
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
    use std::path::Path;

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
        prod_profile.providers.insert(
            "plain".to_string(),
            ProviderConfig::Plain {
                auth_command: None,
                daemon_cache: None,
            },
        );
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
    fn test_local_override_filename_matches_standard_config_names() {
        assert_eq!(
            local_override_filename(Path::new("nested/fnox.toml")),
            Some("fnox.local.toml")
        );
        assert_eq!(
            local_override_filename(Path::new("nested/.fnox.toml")),
            Some(".fnox.local.toml")
        );
    }

    #[test]
    fn test_local_override_filename_rejects_non_standard_config_names() {
        assert_eq!(
            local_override_filename(Path::new("nested/custom.toml")),
            None
        );
        assert_eq!(
            local_override_filename(Path::new("nested/fnox.dev.toml")),
            None
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

    #[test]
    fn test_no_defaults_profile_only_secrets() {
        crate::settings::Settings::reset_for_tests();
        crate::settings::Settings::set_cli_snapshot(crate::settings::CliSnapshot {
            age_key_file: None,
            profile: vec!["prod".to_string()],
            if_missing: None,
            no_defaults: true,
        });

        let mut config = Config::new();
        config
            .secrets
            .insert("DEFAULT_ONLY".to_string(), SecretConfig::new());

        let mut prod_profile = ProfileConfig::new();
        prod_profile
            .secrets
            .insert("PROD_ONLY".to_string(), SecretConfig::new());
        config.profiles.insert("prod".to_string(), prod_profile);

        let secrets = config.get_secrets(&["prod".to_string()]).unwrap();
        assert!(secrets.contains_key("PROD_ONLY"));
        assert!(!secrets.contains_key("DEFAULT_ONLY"));
    }

    #[test]
    fn test_no_defaults_profile_without_section_is_empty() {
        crate::settings::Settings::reset_for_tests();
        crate::settings::Settings::set_cli_snapshot(crate::settings::CliSnapshot {
            age_key_file: None,
            profile: vec!["prod".to_string()],
            if_missing: None,
            no_defaults: true,
        });

        let mut config = Config::new();
        config
            .secrets
            .insert("DEFAULT_ONLY".to_string(), SecretConfig::new());

        let secrets = config.get_secrets(&["prod".to_string()]).unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_find_local_config_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let result = super::find_local_config(dir.path(), &[]);
        assert_eq!(result, dir.path().join("fnox.toml"));
    }

    #[test]
    fn test_find_local_config_only_fnox_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &[]);
        assert_eq!(result, dir.path().join("fnox.toml"));
    }

    #[test]
    fn test_find_local_config_only_local_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.local.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &[]);
        assert_eq!(result, dir.path().join("fnox.local.toml"));
    }

    #[test]
    fn test_find_local_config_both_exist() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.toml"), "").unwrap();
        std::fs::write(dir.path().join("fnox.local.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &[]);
        // Should pick fnox.toml (lowest priority)
        assert_eq!(result, dir.path().join("fnox.toml"));
    }

    #[test]
    fn test_find_local_config_only_dotfile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".fnox.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &[]);
        assert_eq!(result, dir.path().join(".fnox.toml"));
    }

    #[test]
    fn test_find_local_config_profile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.staging.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &["staging".to_string()]);
        assert_eq!(result, dir.path().join("fnox.staging.toml"));
    }

    #[test]
    fn test_find_local_config_profile_with_base() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.toml"), "").unwrap();
        std::fs::write(dir.path().join("fnox.staging.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &["staging".to_string()]);
        // Profile-specific file is preferred when profile is active
        assert_eq!(result, dir.path().join("fnox.staging.toml"));
    }

    #[test]
    fn test_find_local_config_default_profile_with_base() {
        // Default profile should still pick fnox.toml (lowest priority)
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.toml"), "").unwrap();
        std::fs::write(dir.path().join("fnox.local.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &["default".to_string()]);
        assert_eq!(result, dir.path().join("fnox.toml"));
    }

    #[test]
    fn test_find_local_config_profile_only_base_exists() {
        // Profile specified but only base config exists — fall back to it
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &["staging".to_string()]);
        assert_eq!(result, dir.path().join("fnox.toml"));
    }

    #[test]
    fn test_find_local_config_profile_skips_local_file() {
        // When a profile is active and only fnox.local.toml exists,
        // should NOT write there — fall through to creating fnox.toml
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.local.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &["staging".to_string()]);
        assert_eq!(result, dir.path().join("fnox.toml"));
    }

    #[test]
    fn test_find_local_config_no_profile_uses_local_file() {
        // Without a profile, fnox.local.toml is a valid write target
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fnox.local.toml"), "").unwrap();
        let result = super::find_local_config(dir.path(), &[]);
        assert_eq!(result, dir.path().join("fnox.local.toml"));
    }

    #[test]
    fn test_profile_stack_overlays_in_order() {
        let config: Config = toml_edit::de::from_str(
            r#"
[providers.base]
type = "plain"

[secrets.SHARED]
value = "base"

[profiles.aws]
default_provider = "aws_plain"

[profiles.aws.providers.aws_plain]
type = "plain"

[profiles.aws.secrets.AWS_ONLY]
value = "aws"

[profiles.aws.secrets.SHARED]
value = "aws"

[profiles.prod]
default_provider = "prod_plain"

[profiles.prod.providers.prod_plain]
type = "plain"

[profiles.prod.secrets.PROD_ONLY]
value = "prod"

[profiles.prod.secrets.SHARED]
value = "prod"
"#,
        )
        .unwrap();

        let profiles = vec!["aws".to_string(), "prod".to_string()];
        let providers = config.get_providers(&profiles);
        assert!(providers.contains_key("base"));
        assert!(providers.contains_key("aws_plain"));
        assert!(providers.contains_key("prod_plain"));
        assert_eq!(
            config.get_default_provider(&profiles).unwrap(),
            Some("prod_plain".to_string())
        );

        let secrets = config.get_secrets(&profiles).unwrap();
        assert_eq!(
            secrets.get("SHARED").and_then(SecretConfig::value),
            Some("prod")
        );
        assert_eq!(
            secrets.get("AWS_ONLY").and_then(SecretConfig::value),
            Some("aws")
        );
        assert_eq!(
            secrets.get("PROD_ONLY").and_then(SecretConfig::value),
            Some("prod")
        );
    }

    #[test]
    fn filter_secrets_none_allowlist_returns_all() {
        let cfg = McpConfig::default(); // secrets: None
        let mut m = IndexMap::new();
        m.insert("A".to_string(), SecretConfig::new());
        m.insert("B".to_string(), SecretConfig::new());
        let result = cfg.filter_secrets(m.clone());
        assert_eq!(
            result.keys().collect::<Vec<_>>(),
            m.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn filter_secrets_empty_allowlist_returns_empty() {
        let cfg = McpConfig {
            secrets: Some(vec![]),
            ..Default::default()
        };
        let mut m = IndexMap::new();
        m.insert("A".to_string(), SecretConfig::new());
        assert!(cfg.filter_secrets(m).is_empty());
    }

    #[test]
    fn filter_secrets_subset() {
        let cfg = McpConfig {
            secrets: Some(vec!["A".into()]),
            ..Default::default()
        };
        let mut m = IndexMap::new();
        m.insert("A".to_string(), SecretConfig::new());
        m.insert("B".to_string(), SecretConfig::new());
        let result = cfg.filter_secrets(m);
        assert!(result.contains_key("A"));
        assert!(!result.contains_key("B"));
    }

    #[test]
    fn filter_secrets_unknown_allowlist_entry_ignored() {
        let cfg = McpConfig {
            secrets: Some(vec!["A".into(), "NONEXISTENT".into()]),
            ..Default::default()
        };
        let mut m = IndexMap::new();
        m.insert("A".to_string(), SecretConfig::new());
        let result = cfg.filter_secrets(m);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("A"));
    }

    #[test]
    fn mcp_secrets_overlay_replaces_base_not_appends() {
        let base = Config {
            mcp: Some(McpConfig {
                secrets: Some(vec!["A".into()]),
                ..Default::default()
            }),
            ..Config::new()
        };
        let overlay = Config {
            mcp: Some(McpConfig {
                secrets: Some(vec!["B".into()]),
                ..Default::default()
            }),
            ..Config::new()
        };
        let merged = Config::merge_configs(base, overlay).unwrap();
        assert_eq!(
            merged.mcp.unwrap().secrets,
            Some(vec!["B".into()]),
            "overlay must replace, not append, the base allowlist"
        );
    }

    #[test]
    fn mcp_secrets_overlay_without_secrets_preserves_base() {
        let base = Config {
            mcp: Some(McpConfig {
                secrets: Some(vec!["A".into()]),
                ..Default::default()
            }),
            ..Config::new()
        };
        let overlay = Config {
            mcp: Some(McpConfig {
                ..Default::default()
            }),
            ..Config::new()
        };
        let merged = Config::merge_configs(base, overlay).unwrap();
        assert_eq!(merged.mcp.unwrap().secrets, Some(vec!["A".into()]));
    }

    #[test]
    fn test_for_raw_resolve_strips_post_processing_fields() {
        let mut secret = SecretConfig::new();
        secret.set_provider(Some("plain".to_string()));
        secret.set_value(Some(r#"{"user":"admin"}"#.to_string()));
        secret.default = Some("fallback".to_string());
        secret.json_path = Some("user".to_string());
        secret.line = Some(2);
        secret.sync = Some(SyncConfig {
            provider: "age".to_string(),
            value: "encrypted-blob".to_string(),
        });

        let raw = secret.for_raw_resolve();

        assert!(raw.default.is_none());
        assert!(raw.json_path.is_none());
        assert!(raw.line.is_none());
        assert!(raw.sync.is_none());
    }

    #[test]
    fn test_secret_config_line_roundtrip() {
        let toml_input = r#"
[secrets]
USERNAME = { provider = "pass", value = "master", line = 2 }
"#;
        let parsed: Config = toml_edit::de::from_str(toml_input).unwrap();
        let secret = parsed.secrets.get("USERNAME").unwrap();
        assert_eq!(secret.line, Some(2));

        let inline = secret.to_inline_table();
        let rendered = inline.to_string();
        assert!(
            rendered.contains("line = 2"),
            "expected serialized output to contain `line = 2`, got: {rendered}"
        );
    }

    #[test]
    fn test_env_mode_parsing() {
        let toml_input = r#"
[secrets]
SHELL_DEFAULT = { provider = "plain", value = "a" }
SHELL_EXPLICIT = { provider = "plain", value = "b", env = true }
EXEC_ONLY = { provider = "plain", value = "c", env = "exec" }
HIDDEN = { provider = "plain", value = "d", env = false }
"#;
        let parsed: Config = toml_edit::de::from_str(toml_input).unwrap();
        assert_eq!(parsed.secrets["SHELL_DEFAULT"].env, None);
        assert_eq!(parsed.secrets["SHELL_EXPLICIT"].env, Some(EnvMode::Shell));
        assert_eq!(parsed.secrets["EXEC_ONLY"].env, Some(EnvMode::Exec));
        assert_eq!(parsed.secrets["HIDDEN"].env, Some(EnvMode::Never));

        assert!(parsed.secrets["SHELL_DEFAULT"].env_mode().in_shell());
        assert!(parsed.secrets["EXEC_ONLY"].env_mode().in_exec());
        assert!(!parsed.secrets["EXEC_ONLY"].env_mode().in_shell());
        assert!(!parsed.secrets["HIDDEN"].env_mode().in_exec());
    }

    #[test]
    fn test_env_mode_rejects_unknown_string() {
        let toml_input = r#"
[secrets]
BAD = { provider = "plain", value = "a", env = "sometimes" }
"#;
        assert!(toml_edit::de::from_str::<Config>(toml_input).is_err());
    }

    #[test]
    fn test_env_mode_top_level_default_inheritance() {
        let toml_input = r#"
env = "exec"

[secrets]
INHERITED = { provider = "plain", value = "a" }
OPTED_IN = { provider = "plain", value = "b", env = true }
HIDDEN = { provider = "plain", value = "c", env = false }

[profiles.dev.secrets]
DEV_INHERITED = { provider = "plain", value = "d" }
"#;
        let parsed: Config = toml_edit::de::from_str(toml_input).unwrap();
        assert_eq!(parsed.env, Some(EnvMode::Exec));

        let secrets = parsed.get_secrets(&["default".to_string()]).unwrap();
        assert_eq!(secrets["INHERITED"].env_mode(), EnvMode::Exec);
        assert_eq!(secrets["OPTED_IN"].env_mode(), EnvMode::Shell);
        assert_eq!(secrets["HIDDEN"].env_mode(), EnvMode::Never);

        // Only assert on the profile-level secret here: merging top-level
        // secrets into profiles depends on the global no_defaults setting,
        // which other tests mutate concurrently.
        let dev_secrets = parsed.get_secrets(&["dev".to_string()]).unwrap();
        assert_eq!(dev_secrets["DEV_INHERITED"].env_mode(), EnvMode::Exec);
    }

    #[test]
    fn test_env_mode_serialization_roundtrip() {
        let mut secret = SecretConfig::new();
        secret.set_provider(Some("plain".to_string()));
        secret.set_value(Some("v".to_string()));

        secret.env = Some(EnvMode::Exec);
        assert!(
            secret
                .to_inline_table()
                .to_string()
                .contains("env = \"exec\"")
        );

        secret.env = Some(EnvMode::Never);
        assert!(secret.to_inline_table().to_string().contains("env = false"));

        secret.env = Some(EnvMode::Shell);
        assert!(secret.to_inline_table().to_string().contains("env = true"));

        secret.env = None;
        assert!(!secret.to_inline_table().to_string().contains("env"));
    }

    #[test]
    fn test_for_raw_resolve_preserves_non_post_processing_fields() {
        let mut secret = SecretConfig::new();
        secret.set_provider(Some("plain".to_string()));
        secret.set_value(Some("my-secret".to_string()));
        secret.description = Some("A test secret".to_string());
        secret.if_missing = Some(IfMissing::Warn);
        secret.env = Some(EnvMode::Never);
        secret.as_file = true;
        secret.source_path = Some(PathBuf::from("/tmp/fnox.toml"));
        secret.source_is_profile = true;
        secret.default = Some("default-val".to_string());
        secret.json_path = Some("key".to_string());
        secret.sync = Some(SyncConfig {
            provider: "age".to_string(),
            value: "blob".to_string(),
        });

        let raw = secret.for_raw_resolve();

        assert_eq!(raw.provider(), Some("plain"));
        assert_eq!(raw.value(), Some("my-secret"));
        assert_eq!(raw.description.as_deref(), Some("A test secret"));
        assert_eq!(raw.if_missing, Some(IfMissing::Warn));
        assert_eq!(raw.env, Some(EnvMode::Never));
        assert!(raw.as_file);
        assert_eq!(
            raw.source_path.as_deref(),
            Some(Path::new("/tmp/fnox.toml"))
        );
        assert!(raw.source_is_profile);
    }

    #[test]
    fn test_for_raw_resolve_with_no_post_processing_fields() {
        let mut secret = SecretConfig::new();
        secret.set_provider(Some("plain".to_string()));
        secret.set_value(Some("simple-value".to_string()));

        let raw = secret.for_raw_resolve();

        assert_eq!(raw.provider(), Some("plain"));
        assert_eq!(raw.value(), Some("simple-value"));
        assert!(raw.default.is_none());
        assert!(raw.json_path.is_none());
        assert!(raw.sync.is_none());
    }
}
