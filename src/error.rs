use miette::Diagnostic;
use thiserror::Error;

#[derive(Error, Debug, Diagnostic)]
pub enum FnoxError {
    // ========================================================================
    // Configuration Errors
    // ========================================================================
    #[allow(dead_code)]
    #[error("Configuration file not found")]
    #[diagnostic(
        code(fnox::config::not_found),
        help("Run 'fnox init' to create a new configuration file")
    )]
    ConfigFileNotFound { path: std::path::PathBuf },

    #[allow(dead_code)]
    #[error("Failed to read configuration file")]
    #[diagnostic(
        code(fnox::config::read_failed),
        help("Ensure the config file exists and you have read permissions")
    )]
    ConfigReadFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[allow(dead_code)]
    #[error("Failed to write configuration file")]
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
        help("Check the TOML syntax in your fnox.toml file")
    )]
    ConfigParseError {
        #[source]
        source: toml_edit::de::Error,
    },

    #[error("Failed to serialize configuration to TOML")]
    #[diagnostic(code(fnox::config::serialize_failed))]
    ConfigSerializeError {
        #[source]
        source: toml_edit::ser::Error,
    },

    #[allow(dead_code)]
    #[error("Configuration validation failed")]
    #[diagnostic(
        code(fnox::config::validation_failed),
        help("Review the errors below and update your fnox.toml file")
    )]
    ConfigValidationFailed { issues: Vec<String> },

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
            "{init_help}Available actions:\n  • View defined secrets: fnox list -P {profile} --sources\n  • Add this secret: fnox set {key} <value> -P {profile}{suggest}",
            init_help = if config_path.is_none() {
                "No configuration file found. Create one with:\n  • fnox init\n\n"
            } else {
                ""
            },
            suggest = config_path.as_ref()
                .map(|p| format!("\n  • Edit config file: {}", p.display()))
                .unwrap_or_default()
        )
    )]
    SecretNotFound {
        key: String,
        profile: String,
        config_path: Option<std::path::PathBuf>,
    },

    #[allow(dead_code)]
    #[error("Secret '{key}' already exists in profile '{profile}'{}",
        config_path.as_ref()
            .map(|p| format!("\n  Defined in: {}", p.display()))
            .unwrap_or_default()
    )]
    #[diagnostic(
        code(fnox::secret::already_exists),
        help(
            "To update this secret:\n  • Overwrite: fnox set {key} <value> --force -P {profile}{edit}",
            edit = config_path.as_ref()
                .map(|p| format!("\n  • Edit directly: {}", p.display()))
                .unwrap_or_default()
        )
    )]
    SecretAlreadyExists {
        key: String,
        profile: String,
        config_path: Option<std::path::PathBuf>,
    },

    #[allow(dead_code)]
    #[error("Invalid secret key: {key}")]
    #[diagnostic(
        code(fnox::secret::invalid_key),
        help("Secret keys must be valid identifiers (alphanumeric, underscores, hyphens)")
    )]
    InvalidSecretKey { key: String },

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
            "To configure this provider:\n  \
            1. Add provider configuration to your fnox.toml:\n     \
            [profiles.{profile}.providers.{provider}]\n     \
            type = \"age\"  # or other provider type\n  \
            2. Or configure it globally:\n     \
            [providers.{provider}]\n     \
            type = \"age\"{file}",
            file = config_path.as_ref()
                .map(|p| format!("\n  Edit: {}", p.display()))
                .unwrap_or_default()
        )
    )]
    ProviderNotConfigured {
        provider: String,
        profile: String,
        config_path: Option<std::path::PathBuf>,
    },

    #[allow(dead_code)]
    #[error("Provider '{provider}' is not yet implemented")]
    #[diagnostic(
        code(fnox::provider::not_implemented),
        help(
            "This provider is planned but not yet available. Check the roadmap at https://github.com/jdx/fnox"
        ),
        url("https://github.com/jdx/fnox/issues")
    )]
    ProviderNotImplemented { provider: String },

    #[allow(dead_code)]
    #[error("Failed to get secret from {provider} provider")]
    #[diagnostic(code(fnox::provider::get_failed))]
    ProviderGetFailed {
        provider: String,
        key: String,
        details: String,
    },

    #[allow(dead_code)]
    #[error("Failed to set secret in {provider} provider")]
    #[diagnostic(code(fnox::provider::set_failed))]
    ProviderSetFailed {
        provider: String,
        key: String,
        details: String,
    },

    #[allow(dead_code)]
    #[error("Failed to delete secret from {provider} provider")]
    #[diagnostic(code(fnox::provider::delete_failed))]
    ProviderDeleteFailed {
        provider: String,
        key: String,
        details: String,
    },

    #[allow(dead_code)]
    #[error("Failed to list secrets from {provider} provider")]
    #[diagnostic(code(fnox::provider::list_failed))]
    ProviderListFailed { provider: String, details: String },

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
        )
    )]
    ProviderConfigCycle { provider: String, cycle: String },

    #[error("Failed to resolve secret '{secret}' for provider '{provider}' configuration")]
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
        )
    )]
    AgeNotConfigured,

    #[error("Age identity file not found")]
    #[diagnostic(
        code(fnox::encryption::age::identity_not_found),
        help("Create an age identity with: age-keygen -o {}", crate::env::FNOX_CONFIG_DIR.join("age.txt").display()),
        url("https://github.com/FiloSottile/age")
    )]
    AgeIdentityNotFound { path: std::path::PathBuf },

    #[error("Failed to read age identity file")]
    #[diagnostic(
        code(fnox::encryption::age::identity_read_failed),
        help("Ensure the identity file exists and is readable")
    )]
    AgeIdentityReadFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse age identity")]
    #[diagnostic(
        code(fnox::encryption::age::identity_parse_failed),
        help("Ensure the identity file contains a valid age secret key")
    )]
    AgeIdentityParseFailed { details: String },

    #[error("Age encryption failed")]
    #[diagnostic(
        code(fnox::encryption::age::encrypt_failed),
        help("Ensure your age public key is configured correctly")
    )]
    AgeEncryptionFailed { details: String },

    #[error("Age decryption failed")]
    #[diagnostic(
        code(fnox::encryption::age::decrypt_failed),
        help(
            "Ensure you have the correct age identity file or FNOX_AGE_KEY environment variable set"
        )
    )]
    AgeDecryptionFailed { details: String },

    #[allow(dead_code)]
    #[error("No encryption configuration found")]
    #[diagnostic(
        code(fnox::encryption::not_configured),
        help(
            "Add encryption configuration to your fnox.toml:\n  [encryption]\n  type = \"age\"\n  key_file = \"age.txt\""
        )
    )]
    EncryptionNotConfigured,

    #[allow(dead_code)]
    #[error("Unsupported encryption type: {encryption_type}")]
    #[diagnostic(
        code(fnox::encryption::unsupported_type),
        help("Currently only 'age' encryption is supported")
    )]
    UnsupportedEncryptionType { encryption_type: String },

    /// Generic encryption error for cases not covered by specific variants
    #[allow(dead_code)]
    #[error("Encryption error: {0}")]
    #[diagnostic(code(fnox::encryption::error))]
    Encryption(String),

    // ========================================================================
    // Editor Errors
    // ========================================================================
    #[allow(dead_code)]
    #[error("No editor configured")]
    #[diagnostic(
        code(fnox::editor::not_configured),
        help("Set the EDITOR or VISUAL environment variable")
    )]
    EditorNotConfigured,

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
        help("Provide a command to run with your secrets. Example: fnox exec -- npm start")
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
    // Input/Output Errors
    // ========================================================================
    #[allow(dead_code)]
    #[error("Failed to read from stdin")]
    #[diagnostic(code(fnox::io::stdin_read_failed))]
    StdinReadFailed {
        #[source]
        source: std::io::Error,
    },

    #[allow(dead_code)]
    #[error("Failed to write to stdout")]
    #[diagnostic(code(fnox::io::stdout_write_failed))]
    StdoutWriteFailed {
        #[source]
        source: std::io::Error,
    },

    #[allow(dead_code)]
    #[error("Invalid key type: {0}")]
    #[diagnostic(code(fnox::key::invalid_type))]
    InvalidKeyType(String),

    // ========================================================================
    // Generic I/O Errors (fallback)
    // ========================================================================
    #[error("I/O error: {0}")]
    #[diagnostic(code(fnox::io::error))]
    Io(#[from] std::io::Error),

    // ========================================================================
    // JSON/YAML Errors
    // ========================================================================
    #[error("JSON error: {0}")]
    #[diagnostic(code(fnox::json::error))]
    Json(String),

    #[error("YAML error: {0}")]
    #[diagnostic(code(fnox::yaml::error))]
    Yaml(String),
}

// Implement conversions for common error types
impl From<serde_json::Error> for FnoxError {
    fn from(err: serde_json::Error) -> Self {
        FnoxError::Json(err.to_string())
    }
}

impl From<serde_yaml::Error> for FnoxError {
    fn from(err: serde_yaml::Error) -> Self {
        FnoxError::Yaml(err.to_string())
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
