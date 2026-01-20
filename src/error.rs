#![allow(unused_assignments)] // Fields are used by thiserror/miette macros but clippy doesn't see it

use miette::{Diagnostic, NamedSource, SourceSpan};
use std::sync::Arc;
use thiserror::Error;

/// A single validation issue (used with #[related] for multiple error reporting)
#[derive(Error, Debug, Diagnostic)]
#[error("{message}")]
#[diagnostic(code(fnox::config::validation_issue))]
pub struct ValidationIssue {
    pub message: String,
    #[help]
    pub help: Option<String>,
}

impl ValidationIssue {
    pub fn with_help(message: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            help: Some(help.into()),
        }
    }
}

#[derive(Error, Debug, Diagnostic)]
pub enum FnoxError {
    // ========================================================================
    // Configuration Errors
    // ========================================================================
    #[error("Configuration file not found: {}", path.display())]
    #[diagnostic(
        code(fnox::config::not_found),
        help("Run 'fnox init' to create a new configuration file"),
        url("https://fnox.dev/guide/getting-started")
    )]
    ConfigFileNotFound { path: std::path::PathBuf },

    #[error("Failed to read configuration file: {}", path.display())]
    #[diagnostic(
        code(fnox::config::read_failed),
        help("Ensure the config file exists and you have read permissions")
    )]
    ConfigReadFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to write configuration file: {}", path.display())]
    #[diagnostic(
        code(fnox::config::write_failed),
        help("Check that you have write permissions for the config directory")
    )]
    ConfigWriteFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid TOML in configuration file")]
    #[diagnostic(
        code(fnox::config::invalid_toml),
        help("Check the TOML syntax in your fnox.toml file"),
        url("https://fnox.dev/guide/configuration")
    )]
    ConfigParseError {
        #[source]
        source: toml_edit::de::Error,
    },

    /// TOML parse error with source code context for precise error location display.
    #[error("{message}")]
    #[diagnostic(
        code(fnox::config::invalid_toml),
        help("Check the TOML syntax in your configuration file")
    )]
    ConfigParseErrorWithSource {
        message: String,
        #[source_code]
        src: Arc<NamedSource<Arc<String>>>,
        #[label("parse error here")]
        span: SourceSpan,
    },

    #[error("Failed to serialize configuration to TOML")]
    #[diagnostic(code(fnox::config::serialize_failed))]
    ConfigSerializeError {
        #[source]
        source: toml_edit::ser::Error,
    },

    /// Configuration validation failed with one or more issues.
    /// Uses #[related] to display all validation issues together.
    #[error("Configuration validation failed ({})", pluralizer::pluralize("issue", std::cmp::min(issues.len(), isize::MAX as usize) as isize, true))]
    #[diagnostic(
        code(fnox::config::validation_failed),
        help("Fix the issues above in your fnox.toml file"),
        url("https://fnox.dev/guide/configuration")
    )]
    ConfigValidationFailed {
        #[related]
        issues: Vec<ValidationIssue>,
    },

    /// Backward compatibility for ConfigNotFound with custom message/help
    #[error("{message}")]
    #[diagnostic(help("{help}"))]
    ConfigNotFound { message: String, help: String },

    /// Generic config error for cases not covered by specific variants
    #[error("Configuration error: {0}")]
    #[diagnostic(code(fnox::config::error))]
    Config(String),

    // ========================================================================
    // Profile Errors
    // ========================================================================

    // ========================================================================
    // Secret Errors
    // ========================================================================
    #[error("Secret '{key}' not found in profile '{profile}'{}",
        config_path.as_ref()
            .map(|p| format!("\n  Config file: {}", p.display()))
            .unwrap_or_else(|| "\n  (not defined in any config file)".to_string())
    )]
    #[diagnostic(
        code(fnox::secret::not_found),
        help(
            "{suggestion}{init_help}Available actions:\n  • View defined secrets: fnox list -P {profile} --sources\n  • Add this secret: fnox set {key} <value> -P {profile}{file_suggest}",
            suggestion = suggestion.as_ref()
                .map(|s| format!("{}\n\n", s))
                .unwrap_or_default(),
            init_help = if config_path.is_none() {
                "No configuration file found. Create one with:\n  • fnox init\n\n"
            } else {
                ""
            },
            file_suggest = config_path.as_ref()
                .map(|p| format!("\n  • Edit config file: {}", p.display()))
                .unwrap_or_default()
        ),
        url("https://fnox.dev/guide/secrets")
    )]
    SecretNotFound {
        key: String,
        profile: String,
        config_path: Option<std::path::PathBuf>,
        suggestion: Option<String>,
    },

    // ========================================================================
    // Provider Errors
    // ========================================================================
    #[error("Provider '{provider}' not configured in profile '{profile}'{}",
        config_path.as_ref()
            .map(|p| format!("\n  Config file: {}", p.display()))
            .unwrap_or_else(|| "\n  (provider not defined in any config file)".to_string())
    )]
    #[diagnostic(
        code(fnox::provider::not_configured),
        help(
            "{suggestion}To configure this provider:\n  \
            1. Add provider configuration to your fnox.toml:\n     \
            [profiles.{profile}.providers.{provider}]\n     \
            type = \"age\"  # or other provider type\n  \
            2. Or configure it globally:\n     \
            [providers.{provider}]\n     \
            type = \"age\"{file}",
            suggestion = suggestion.as_ref()
                .map(|s| format!("{}\n\n", s))
                .unwrap_or_default(),
            file = config_path.as_ref()
                .map(|p| format!("\n  Edit: {}", p.display()))
                .unwrap_or_default()
        ),
        url("https://fnox.dev/guide/providers")
    )]
    ProviderNotConfigured {
        provider: String,
        profile: String,
        config_path: Option<std::path::PathBuf>,
        suggestion: Option<String>,
    },

    /// Provider not configured error with source code context showing where the provider is referenced.
    #[error("Provider '{provider}' not configured in profile '{profile}'")]
    #[diagnostic(
        code(fnox::provider::not_configured),
        help(
            "{suggestion}Add the provider to your config:\n  \
            [providers.{provider}]\n  \
            type = \"age\"  # or other provider type",
            suggestion = suggestion.as_ref()
                .map(|s| format!("{}\n\n", s))
                .unwrap_or_default()
        )
    )]
    ProviderNotConfiguredWithSource {
        provider: String,
        profile: String,
        suggestion: Option<String>,
        #[source_code]
        src: Arc<NamedSource<Arc<String>>>,
        #[label("provider '{provider}' referenced here")]
        span: SourceSpan,
    },

    /// Default provider not found error with source code context showing where it was configured.
    #[error("Default provider '{provider}' not found in profile '{profile}'")]
    #[diagnostic(
        code(fnox::config::default_provider_not_found),
        help(
            "The configured default_provider references a provider that doesn't exist.\n\
            Add the provider to your config:\n  \
            [providers.{provider}]\n  \
            type = \"age\"  # or other provider type"
        )
    )]
    DefaultProviderNotFoundWithSource {
        provider: String,
        profile: String,
        #[source_code]
        src: Arc<NamedSource<Arc<String>>>,
        #[label("default_provider '{provider}' set here, but no such provider exists")]
        span: SourceSpan,
    },

    /// Generic provider error for cases not covered by specific variants
    #[error("Provider error: {0}")]
    #[diagnostic(code(fnox::provider::error))]
    Provider(String),

    #[error("Circular dependency detected in provider configuration for '{provider}'")]
    #[diagnostic(
        code(fnox::provider::config_cycle),
        help(
            "Resolution path: {cycle}\n\
            Break the cycle by using a literal value or environment variable for one provider."
        ),
        url("https://fnox.dev/guide/secret-references")
    )]
    ProviderConfigCycle { provider: String, cycle: String },

    #[error(
        "Failed to resolve secret '{secret}' for provider '{provider}' configuration: {details}"
    )]
    #[diagnostic(
        code(fnox::provider::config_resolution_failed),
        help(
            "Ensure the secret '{secret}' is defined in your config or as an environment variable"
        )
    )]
    ProviderConfigResolutionFailed {
        provider: String,
        secret: String,
        details: String,
    },

    // ========================================================================
    // Encryption Errors
    // ========================================================================
    #[error("Age encryption is not configured")]
    #[diagnostic(
        code(fnox::encryption::age::not_configured),
        help(
            "Add age encryption to your config:\n  [encryption]\n  type = \"age\"\n  key_file = \"age.txt\""
        ),
        url("https://fnox.dev/providers/age")
    )]
    AgeNotConfigured,

    #[error("Age identity file not found: {}", path.display())]
    #[diagnostic(
        code(fnox::encryption::age::identity_not_found),
        help("Create an age identity with: age-keygen -o {}", crate::env::FNOX_CONFIG_DIR.join("age.txt").display()),
        url("https://github.com/FiloSottile/age")
    )]
    AgeIdentityNotFound { path: std::path::PathBuf },

    #[error("Failed to read age identity file: {}", path.display())]
    #[diagnostic(
        code(fnox::encryption::age::identity_read_failed),
        help("Ensure the identity file exists and is readable")
    )]
    AgeIdentityReadFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse age identity: {details}")]
    #[diagnostic(
        code(fnox::encryption::age::identity_parse_failed),
        help("Ensure the identity file contains a valid age secret key")
    )]
    AgeIdentityParseFailed { details: String },

    #[error("Age encryption failed: {details}")]
    #[diagnostic(
        code(fnox::encryption::age::encrypt_failed),
        help("Ensure your age public key is configured correctly"),
        url("https://fnox.dev/providers/age")
    )]
    AgeEncryptionFailed { details: String },

    #[error("Age decryption failed: {details}")]
    #[diagnostic(
        code(fnox::encryption::age::decrypt_failed),
        help(
            "Ensure you have the correct age identity file or FNOX_AGE_KEY environment variable set"
        ),
        url("https://fnox.dev/providers/age")
    )]
    AgeDecryptionFailed { details: String },

    // ========================================================================
    // Editor Errors
    // ========================================================================
    #[error("Failed to launch editor: {editor}")]
    #[diagnostic(code(fnox::editor::launch_failed))]
    EditorLaunchFailed {
        editor: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Editor exited with non-zero status: {status}")]
    #[diagnostic(code(fnox::editor::exit_failed))]
    EditorExitFailed { editor: String, status: i32 },

    // ========================================================================
    // Command Execution Errors
    // ========================================================================
    #[error("No command specified")]
    #[diagnostic(
        code(fnox::command::not_specified),
        help("Provide a command to run with your secrets. Example: fnox exec -- npm start"),
        url("https://fnox.dev/guide/exec")
    )]
    CommandNotSpecified,

    #[error("Command execution failed: {command}")]
    #[diagnostic(code(fnox::command::execution_failed))]
    CommandExecutionFailed {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Command exited with status {status}: {command}")]
    #[diagnostic(code(fnox::command::exit_failed))]
    CommandExitFailed { command: String, status: i32 },

    // ========================================================================
    // Import Errors
    // ========================================================================
    #[error("When importing from stdin, --force or --dry-run is required")]
    #[diagnostic(
        code(fnox::import::stdin_requires_force),
        help(
            "Stdin is consumed during import and cannot be used for the confirmation prompt.\n\n\
            Use: fnox import --force < input.env\n\
            Or:  fnox import --dry-run < input.env  (to preview without changes)\n\
            Or:  cat input.env | fnox import --force"
        )
    )]
    ImportStdinRequiresForce,

    #[error("Invalid regex filter pattern: {pattern}: {details}")]
    #[diagnostic(
        code(fnox::import::invalid_regex),
        help("Ensure the filter is a valid regular expression")
    )]
    InvalidRegexFilter { pattern: String, details: String },

    #[error("Failed to read import source: {}", path.display())]
    #[diagnostic(
        code(fnox::import::read_failed),
        help("Ensure the file exists and you have read permissions")
    )]
    ImportReadFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to encrypt secret '{key}' with provider '{provider}': {details}")]
    #[diagnostic(
        code(fnox::import::encryption_failed),
        help("Check the provider configuration and ensure the encryption key is available")
    )]
    ImportEncryptionFailed {
        key: String,
        provider: String,
        details: String,
    },

    #[error("Provider '{provider}' cannot be used for import")]
    #[diagnostic(code(fnox::import::provider_unsupported), help("{help}"))]
    ImportProviderUnsupported { provider: String, help: String },

    #[error("Failed to create directory: {}", path.display())]
    #[diagnostic(
        code(fnox::io::create_dir_failed),
        help("Ensure you have write permissions for the parent directory")
    )]
    CreateDirFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    // ========================================================================
    // Input/Output Errors
    // ========================================================================
    #[error("Failed to write export to file: {}", path.display())]
    #[diagnostic(
        code(fnox::export::write_failed),
        help("Ensure you have write permissions for the output path")
    )]
    ExportWriteFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read from stdin")]
    #[diagnostic(code(fnox::io::stdin_read_failed))]
    StdinReadFailed {
        #[source]
        source: std::io::Error,
    },

    // ========================================================================
    // Generic I/O Errors (fallback)
    // ========================================================================
    #[error("I/O error: {0}")]
    #[diagnostic(code(fnox::io::error))]
    Io(#[from] std::io::Error),

    // ========================================================================
    // JSON/YAML Errors
    // ========================================================================
    #[error("JSON error")]
    #[diagnostic(code(fnox::json::error))]
    Json {
        #[source]
        source: serde_json::Error,
    },

    #[error("YAML error")]
    #[diagnostic(code(fnox::yaml::error))]
    Yaml {
        #[source]
        source: serde_yaml::Error,
    },

    #[error("TOML serialization error")]
    #[diagnostic(code(fnox::toml::error))]
    Toml {
        #[source]
        source: toml_edit::ser::Error,
    },
}

// Implement conversions for common error types
impl From<serde_json::Error> for FnoxError {
    fn from(source: serde_json::Error) -> Self {
        FnoxError::Json { source }
    }
}

impl From<serde_yaml::Error> for FnoxError {
    fn from(source: serde_yaml::Error) -> Self {
        FnoxError::Yaml { source }
    }
}

impl From<toml_edit::de::Error> for FnoxError {
    fn from(source: toml_edit::de::Error) -> Self {
        FnoxError::ConfigParseError { source }
    }
}

impl From<toml_edit::ser::Error> for FnoxError {
    fn from(source: toml_edit::ser::Error) -> Self {
        FnoxError::ConfigSerializeError { source }
    }
}

// Keep this for backward compatibility with existing miette::miette!() calls
// We'll phase these out in Phase 2
impl From<miette::ErrReport> for FnoxError {
    fn from(err: miette::ErrReport) -> Self {
        FnoxError::Config(format!("{}", err))
    }
}

pub type Result<T> = std::result::Result<T, FnoxError>;
