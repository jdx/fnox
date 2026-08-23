// Settings management for fnox
//
// The settings are declared once, on `SettingsData` below: `#[derive(usage::Config)]`
// generates the usage-config registry, the reader that fills the struct from a resolution,
// and the spec `config` block that documents them. There is no settings.toml and no build
// script generator left to keep in step with this file.
//
// Resolution is usage-config's single merge, with the precedence fnox has always had:
// 1. Default values (lowest precedence)
// 2. Environment variables
// 3. CLI flags (highest precedence)

use arc_swap::ArcSwap;
use miette::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};
use usage_rs::config::{CliLayer, EnvLayer, Layers, SourceKind, Value, resolve};

/// Every setting fnox has.
///
/// The struct is the registry: `SETTINGS_PROPS`, `SETTINGS_REGISTRY`, `read`, and
/// `spec_kdl` are generated from these fields, and the CLI's emitted spec carries the
/// `config` block through `#[usage(config = ...)]` on the root.
#[derive(usage_rs::Config, Debug, Clone, PartialEq)]
pub struct SettingsData {
    /// Path to a file containing the age encryption key.
    ///
    /// This can be set via:
    /// - CLI flag: --age-key-file <path>
    /// - Environment variable: FNOX_AGE_KEY_FILE
    ///
    /// Priority (highest to lowest): CLI > Environment > Default
    #[usage(
        env = "FNOX_AGE_KEY_FILE",
        cli("--age-key-file"),
        since = "0.1.0",
        example("fnox get MY_SECRET --age-key-file ~/.age/key.txt"),
        example("FNOX_AGE_KEY_FILE=~/.age/key.txt fnox get MY_SECRET")
    )]
    pub age_key_file: Option<PathBuf>,

    /// Configuration profile to use for secrets retrieval.
    ///
    /// Profiles allow you to maintain multiple configurations (e.g., dev, staging, prod)
    /// in a single fnox.toml file.
    ///
    /// Priority (highest to lowest): CLI > Environment > Default
    #[usage(
        env = "FNOX_PROFILE",
        cli("--profile", "-P"),
        parse = "list_by_comma",
        default("default"),
        since = "0.1.0",
        example("fnox get MY_SECRET --profile production"),
        example("FNOX_PROFILE=staging fnox get MY_SECRET")
    )]
    pub profile: Vec<String>,

    /// When a non-default profile is selected, do not merge top-level [secrets] into
    /// the profile. Only [profiles.<name>.secrets] will be used.
    ///
    /// Priority (highest to lowest): CLI > Environment > Default
    #[usage(
        env = "FNOX_NO_DEFAULTS",
        cli("--no-defaults"),
        default = false,
        since = "1.12.0",
        example("fnox exec --profile dev --no-defaults -- ./my-app"),
        example("FNOX_NO_DEFAULTS=true fnox exec --profile dev -- ./my-app")
    )]
    pub no_defaults: bool,

    /// Control output level for shell integration.
    ///
    /// Available modes:
    /// - "none" - No output from shell integration
    /// - "normal" - Show summary when secrets are loaded/unloaded (default)
    /// - "debug" - Show detailed information including early-exit reasons
    ///
    /// Priority: Environment > Default
    #[usage(
        env = "FNOX_SHELL_OUTPUT",
        default = "normal",
        since = "0.1.0",
        example("FNOX_SHELL_OUTPUT=none fnox activate bash"),
        example("FNOX_SHELL_OUTPUT=debug fnox activate zsh")
    )]
    pub shell_integration_output: String,

    /// Runtime override for if_missing behavior when a secret cannot be resolved.
    ///
    /// Available modes:
    /// - "error" - Fail the command if a secret cannot be resolved
    /// - "warn" - Print a warning and continue
    /// - "ignore" - Silently skip missing secrets
    ///
    /// Priority (highest to lowest): CLI flag > Environment > Secret level >
    /// Top-level config > FNOX_IF_MISSING_DEFAULT > Default (warn)
    #[usage(
        env = "FNOX_IF_MISSING",
        cli("--if-missing"),
        since = "1.1.0",
        example("fnox exec --if-missing error -- ./my-app"),
        example("FNOX_IF_MISSING=ignore fnox exec -- ./my-app")
    )]
    pub if_missing: Option<String>,

    /// HTTP request timeout in seconds for lease backend API calls (Vault, GCP IAM, etc.).
    ///
    /// Prevents fnox exec from hanging indefinitely on slow or unreachable servers.
    /// Set to "0" to disable the timeout (not recommended).
    ///
    /// Priority: Environment > Default
    #[usage(
        env = "FNOX_HTTP_TIMEOUT",
        default = "30s",
        since = "1.16.0",
        example("FNOX_HTTP_TIMEOUT=60s fnox exec -- ./my-app"),
        example("FNOX_HTTP_TIMEOUT=10s fnox lease create my-lease --duration 1h")
    )]
    pub http_timeout: String,

    /// Base default behavior when a secret cannot be resolved and not specified in config.
    ///
    /// Available modes:
    /// - "error" - Fail the command if a secret cannot be resolved
    /// - "warn" - Print a warning and continue (default)
    /// - "ignore" - Silently skip missing secrets
    ///
    /// Priority (highest to lowest): CLI flag > FNOX_IF_MISSING > Secret level >
    /// Top-level config > FNOX_IF_MISSING_DEFAULT > Default (warn)
    #[usage(
        env = "FNOX_IF_MISSING_DEFAULT",
        since = "1.1.0",
        example("export FNOX_IF_MISSING_DEFAULT=error  # Strict by default"),
        example("export FNOX_IF_MISSING_DEFAULT=ignore  # Lenient by default")
    )]
    pub if_missing_default: Option<String>,
}

pub use SettingsData as GeneratedSettings;

pub type SettingsSnapshot = Arc<SettingsData>;

// Global cached settings instance using ArcSwap for safe reloading
static GLOBAL_SETTINGS: LazyLock<ArcSwap<SettingsData>> =
    LazyLock::new(|| ArcSwap::from_pointee(default_settings()));

// Track whether we've initialized with real settings
static INITIALIZED: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));

/// CLI snapshot captured from parsed command-line arguments.
///
/// The programmatic form of the command-line layer, for callers that hold typed values
/// rather than argv: the daemon applies a client's request through this, and tests set it
/// directly. `fnox`'s own `main` hands over the layer the parser built instead, which is
/// how "the flag was left off" and "the flag said no" stay distinguishable.
#[derive(Debug, Clone, Default)]
pub struct CliSnapshot {
    pub age_key_file: Option<PathBuf>,
    pub profile: Vec<String>,
    pub if_missing: Option<String>,
    pub no_defaults: bool,
}

impl CliSnapshot {
    /// This snapshot as the command-line layer of a resolution.
    ///
    /// Only what was given contributes, because the command line outranks every other
    /// layer: an entry it did not earn would silently beat an environment variable the
    /// user did set.
    fn into_layer(self) -> CliLayer {
        let mut layer = CliLayer::new(std::iter::empty::<(String, String)>());
        if let Some(age_key_file) = self.age_key_file {
            layer = layer.with_value(
                "age_key_file",
                Value::String(age_key_file.display().to_string()),
            );
        }
        if !self.profile.is_empty() {
            layer = layer.with_value(
                "profile",
                Value::List(self.profile.into_iter().map(Value::String).collect()),
            );
        }
        if let Some(if_missing) = self.if_missing {
            layer = layer.with_value("if_missing", Value::String(if_missing));
        }
        if self.no_defaults {
            layer = layer.with_value("no_defaults", Value::Bool(true));
        }
        layer
    }
}

static CLI_LAYER: LazyLock<Mutex<Option<CliLayer>>> = LazyLock::new(|| Mutex::new(None));

/// The declared defaults, read the same way any other resolution is.
fn default_settings() -> SettingsData {
    let resolved = resolve(SettingsData::SETTINGS_REGISTRY, Layers::new())
        .expect("no layers were given, so there is nothing to fail");
    SettingsData::read(&resolved).expect("every fnox setting has a declared default or is optional")
}

fn validate_env_profiles(profile: &mut Vec<String>) {
    profile.retain(|name| {
        if name.is_empty() {
            return false;
        }
        if !crate::env::is_valid_profile_name(name) {
            tracing::warn!(
                "Warning: Invalid profile name '{}' in FNOX_PROFILE ignored (contains path separators or invalid characters)",
                name
            );
            return false;
        }
        true
    });
    if profile.is_empty() {
        *profile = default_settings().profile;
    }
}

/// Main Settings interface
pub struct Settings;

impl Settings {
    /// Get the current settings snapshot (panics on error)
    pub fn get() -> Arc<SettingsData> {
        Self::try_get().expect("Failed to load configuration")
    }

    /// Try to get the current settings snapshot (returns error instead of panicking)
    pub fn try_get() -> Result<Arc<SettingsData>> {
        Self::get_snapshot()
    }

    fn get_snapshot() -> Result<SettingsSnapshot> {
        // Check if we need to initialize
        let mut initialized = INITIALIZED.lock().unwrap();
        if !*initialized {
            // First access - initialize with all sources
            let new_settings = Arc::new(Self::build_from_all_sources()?);
            GLOBAL_SETTINGS.store(new_settings.clone());
            *initialized = true;
            return Ok(new_settings);
        }
        drop(initialized); // Release the lock early

        // Already initialized - return the cached value
        Ok(GLOBAL_SETTINGS.load_full())
    }

    /// Set the command-line layer (called after parsing CLI args).
    pub fn set_cli_layer(layer: CliLayer) {
        *CLI_LAYER.lock().unwrap() = Some(layer);
        if *INITIALIZED.lock().unwrap() {
            match Self::build_from_all_sources() {
                Ok(settings) => GLOBAL_SETTINGS.store(Arc::new(settings)),
                Err(e) => {
                    tracing::warn!("failed to reload settings after CLI layer update: {e}")
                }
            }
        }
    }

    /// Set the CLI snapshot, for a caller holding typed values rather than argv.
    pub fn set_cli_snapshot(snapshot: CliSnapshot) {
        Self::set_cli_layer(snapshot.into_layer());
    }

    /// Build settings by merging all sources
    fn build_from_all_sources() -> Result<SettingsData> {
        let env = EnvLayer::from_process();
        let cli_guard = CLI_LAYER.lock().unwrap();

        let mut layers = Layers::new();
        if let Some(cli) = cli_guard.as_ref() {
            layers = layers.then(cli);
        }
        let layers = layers.then(&env);

        let resolved = resolve(SettingsData::SETTINGS_REGISTRY, layers)
            .map_err(|e| miette::miette!("failed to resolve settings: {e}"))?;
        for warning in usage_rs::config::explain::warnings(&resolved) {
            tracing::warn!("{warning}");
        }
        let mut settings = SettingsData::read(&resolved)
            .map_err(|e| miette::miette!("failed to read settings: {e}"))?;

        // Environment-supplied values keep the conveniences the hand-written env reader
        // had, applied by provenance so a CLI-supplied value is left exactly as typed.
        let registry = SettingsData::SETTINGS_REGISTRY;
        let from_env = |key: &str| {
            registry.lookup(key).is_some_and(|found| {
                resolved
                    .origin(found.id)
                    .is_some_and(|origin| origin.kind == SourceKind::ENV)
            })
        };

        // Expand tilde (~) in paths to the user's home directory
        if from_env("age_key_file") {
            settings.age_key_file = settings
                .age_key_file
                .map(|path| Self::expand_path(&path.display().to_string()));
        }

        // Skip invalid profile names, with the same warning `FNOX_PROFILE` has always
        // produced for them.
        if from_env("profile") {
            validate_env_profiles(&mut settings.profile);
        }

        Ok(settings)
    }

    /// Expand tilde (~) in path strings to the user's home directory
    fn expand_path(path: &str) -> PathBuf {
        shellexpand::tilde(path).into_owned().into()
    }

    #[cfg(test)]
    pub fn reset_for_tests() {
        GLOBAL_SETTINGS.store(Arc::new(default_settings()));
        *INITIALIZED.lock().unwrap() = false;
        *CLI_LAYER.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = default_settings();
        assert_eq!(settings.profile, vec!["default".to_string()]);
        assert_eq!(settings.age_key_file, None);
        assert!(!settings.no_defaults);
        assert_eq!(settings.shell_integration_output, "normal");
        assert_eq!(settings.http_timeout, "30s");
        assert_eq!(settings.if_missing, None);
        assert_eq!(settings.if_missing_default, None);
    }

    #[test]
    fn test_cli_layer_overrides_defaults() {
        let cli = CliSnapshot {
            age_key_file: Some(PathBuf::from("/cli/key.txt")),
            profile: vec!["prod".to_string()],
            if_missing: None,
            no_defaults: false,
        }
        .into_layer();

        let resolved =
            resolve(SettingsData::SETTINGS_REGISTRY, Layers::new().then(&cli)).expect("resolves");
        let settings = SettingsData::read(&resolved).expect("reads");

        assert_eq!(settings.age_key_file, Some(PathBuf::from("/cli/key.txt")));
        assert_eq!(settings.profile, vec!["prod".to_string()]);
        // Not given, so the defaults stand.
        assert!(!settings.no_defaults);
        assert_eq!(settings.http_timeout, "30s");
    }

    #[test]
    fn test_cli_layer_beats_env() {
        let cli = CliSnapshot {
            age_key_file: Some(PathBuf::from("/cli/key.txt")),
            ..Default::default()
        }
        .into_layer();
        let env = EnvLayer::new([("FNOX_AGE_KEY_FILE".to_string(), "/env/key.txt".to_string())]);

        let resolved = resolve(
            SettingsData::SETTINGS_REGISTRY,
            Layers::new().then(&cli).then(&env),
        )
        .expect("resolves");
        let settings = SettingsData::read(&resolved).expect("reads");

        // CLI should win
        assert_eq!(settings.age_key_file, Some(PathBuf::from("/cli/key.txt")));
    }

    #[test]
    fn test_env_fills_what_cli_left_alone() {
        let cli = CliLayer::new(std::iter::empty::<(String, String)>());
        let env = EnvLayer::new([
            ("FNOX_AGE_KEY_FILE".to_string(), "/env/key.txt".to_string()),
            ("FNOX_PROFILE".to_string(), "staging, prod".to_string()),
            // Preserve fnox's pre-usage-config behavior: environment boolean words
            // are case-insensitive.
            ("FNOX_NO_DEFAULTS".to_string(), "TRUE".to_string()),
        ]);

        let resolved = resolve(
            SettingsData::SETTINGS_REGISTRY,
            Layers::new().then(&cli).then(&env),
        )
        .expect("resolves");
        let settings = SettingsData::read(&resolved).expect("reads");

        assert_eq!(settings.age_key_file, Some(PathBuf::from("/env/key.txt")));
        assert_eq!(
            settings.profile,
            vec!["staging".to_string(), "prod".to_string()],
            "FNOX_PROFILE is a comma-separated list"
        );
        assert!(settings.no_defaults);
    }

    #[test]
    fn test_invalid_env_profiles_fall_back_to_default() {
        let env = EnvLayer::new([("FNOX_PROFILE".to_string(), "../bad,/also-bad".to_string())]);
        let resolved =
            resolve(SettingsData::SETTINGS_REGISTRY, Layers::new().then(&env)).expect("resolves");
        let mut settings = SettingsData::read(&resolved).expect("reads");

        validate_env_profiles(&mut settings.profile);

        assert_eq!(settings.profile, vec!["default".to_string()]);
    }

    #[test]
    fn test_expand_path_with_tilde() {
        // Test tilde expansion
        let expanded = Settings::expand_path("~/test/path");
        let home = dirs::home_dir().unwrap();
        assert_eq!(expanded, home.join("test/path"));

        // Test without tilde (should remain unchanged)
        let expanded = Settings::expand_path("/absolute/path");
        assert_eq!(expanded, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_registry_matches_docs() {
        // The emitted config block is the settings documentation now; make sure the
        // registry holds what the old settings.toml declared.
        let keys: Vec<&str> = SettingsData::SETTINGS_PROPS
            .iter()
            .map(|meta| meta.key)
            .collect();
        assert_eq!(
            keys,
            vec![
                "age_key_file",
                "profile",
                "no_defaults",
                "shell_integration_output",
                "if_missing",
                "http_timeout",
                "if_missing_default",
            ]
        );
    }
}
