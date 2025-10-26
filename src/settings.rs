// Settings management for fnox
// Based on the pattern from hk (https://github.com/jdx/hk)
//
// This module provides a centralized settings system that merges configuration from:
// 1. Default values (lowest precedence)
// 2. Config files (fnox.toml)
// 3. Environment variables
// 4. CLI flags (highest precedence)

use arc_swap::ArcSwap;
use miette::Result;
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};

// Include generated settings code
mod generated {
    pub(super) mod settings {
        include!(concat!(env!("OUT_DIR"), "/generated/settings.rs"));
    }
    pub(super) mod settings_merge {
        include!(concat!(env!("OUT_DIR"), "/generated/settings_merge.rs"));
    }
    pub(super) mod settings_meta {
        include!(concat!(env!("OUT_DIR"), "/generated/settings_meta.rs"));
    }
}

pub use generated::settings::Settings as GeneratedSettings;
use generated::settings_merge::{SettingValue, SourceMap};
use generated::settings_meta::SETTINGS_META;

pub type SettingsSnapshot = Arc<GeneratedSettings>;

// Global cached settings instance using ArcSwap for safe reloading
static GLOBAL_SETTINGS: LazyLock<ArcSwap<GeneratedSettings>> =
    LazyLock::new(|| ArcSwap::from_pointee(GeneratedSettings::default()));

// Track whether we've initialized with real settings
static INITIALIZED: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));

/// CLI snapshot captured from parsed command-line arguments
#[derive(Debug, Clone, Default)]
pub struct CliSnapshot {
    pub age_key_file: Option<std::path::PathBuf>,
    pub profile: Option<String>,
}

static CLI_SNAPSHOT: LazyLock<Mutex<Option<CliSnapshot>>> = LazyLock::new(|| Mutex::new(None));

/// Main Settings interface
pub struct Settings;

impl Settings {
    /// Get the current settings snapshot (panics on error)
    pub fn get() -> Arc<GeneratedSettings> {
        Self::try_get().expect("Failed to load configuration")
    }

    /// Try to get the current settings snapshot (returns error instead of panicking)
    pub fn try_get() -> Result<Arc<GeneratedSettings>> {
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

    /// Set the CLI snapshot (called after parsing CLI args)
    pub fn set_cli_snapshot(snapshot: CliSnapshot) {
        *CLI_SNAPSHOT.lock().unwrap() = Some(snapshot);
    }

    /// Build settings by merging all sources
    fn build_from_all_sources() -> Result<GeneratedSettings> {
        let defaults = GeneratedSettings::default();
        let env_map = Self::collect_env_map()?;
        let cli_map = Self::collect_cli_map();

        Ok(Self::merge_settings(&defaults, &env_map, &cli_map))
    }

    /// Expand tilde (~) in path strings to the user's home directory
    fn expand_path(path: &str) -> std::path::PathBuf {
        shellexpand::tilde(path).into_owned().into()
    }

    /// Collect settings from environment variables
    fn collect_env_map() -> Result<SourceMap> {
        let mut map = SourceMap::new();

        for (setting_name, meta) in SETTINGS_META.iter() {
            for env_var in meta.sources.env {
                if let Ok(val) = std::env::var(env_var) {
                    match meta.typ {
                        "string" => {
                            map.insert(setting_name, SettingValue::String(val));
                        }
                        "option<string>" => {
                            map.insert(setting_name, SettingValue::OptionString(Some(val)));
                        }
                        "path" => {
                            map.insert(setting_name, SettingValue::Path(Self::expand_path(&val)));
                        }
                        "option<path>" => {
                            map.insert(
                                setting_name,
                                SettingValue::OptionPath(Some(Self::expand_path(&val))),
                            );
                        }
                        "bool" => {
                            // Parse bool from env var (accept "true", "1", "yes", "on")
                            let bool_val =
                                matches!(val.to_lowercase().as_str(), "true" | "1" | "yes" | "on");
                            map.insert(setting_name, SettingValue::Bool(bool_val));
                        }
                        _ => {
                            // Ignore unknown types
                        }
                    }
                    break; // First matching env var wins
                }
            }
        }

        Ok(map)
    }

    /// Collect settings from CLI snapshot
    fn collect_cli_map() -> SourceMap {
        let mut map = SourceMap::new();

        if let Some(snapshot) = CLI_SNAPSHOT.lock().unwrap().clone() {
            if let Some(age_key_file) = snapshot.age_key_file {
                map.insert("age_key_file", SettingValue::OptionPath(Some(age_key_file)));
            }

            if let Some(profile) = snapshot.profile {
                map.insert("profile", SettingValue::String(profile));
            }
        }

        map
    }

    /// Merge settings from all sources
    /// Precedence: CLI > Env > Defaults
    fn merge_settings(
        defaults: &GeneratedSettings,
        env: &SourceMap,
        cli: &SourceMap,
    ) -> GeneratedSettings {
        let mut val =
            serde_json::to_value(defaults.clone()).unwrap_or_else(|_| serde_json::json!({}));

        // Helper to set a value
        fn set_value(val: &mut serde_json::Value, field: &str, v: &SettingValue) {
            let new_v = match v {
                SettingValue::String(s) => serde_json::json!(s),
                SettingValue::OptionString(opt) => serde_json::json!(opt),
                SettingValue::Path(p) => serde_json::json!(p.display().to_string()),
                SettingValue::OptionPath(opt) => {
                    serde_json::json!(opt.as_ref().map(|p| p.display().to_string()))
                }
                SettingValue::Bool(b) => serde_json::json!(b),
            };

            if let Some(obj) = val.as_object_mut() {
                obj.insert(field.to_string(), new_v);
            }
        }

        // Apply layers in precedence order (low to high): defaults < env < cli
        for (name, _meta) in SETTINGS_META.iter() {
            let field = *name;

            // Apply env
            if let Some(sv) = env.get(field) {
                set_value(&mut val, field, sv);
            }

            // Apply cli (overrides env)
            if let Some(sv) = cli.get(field) {
                set_value(&mut val, field, sv);
            }
        }

        serde_json::from_value(val).unwrap_or_else(|_| defaults.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = GeneratedSettings::default();
        assert_eq!(settings.profile, "default");
        assert_eq!(settings.age_key_file, None);
    }

    #[test]
    fn test_settings_merge_precedence() {
        let defaults = GeneratedSettings {
            age_key_file: None,
            profile: "default".to_string(),
            shell_integration_output: "normal".to_string(),
        };

        let mut env = SourceMap::new();
        env.insert(
            "age_key_file",
            SettingValue::OptionPath(Some(std::path::PathBuf::from("/env/key.txt"))),
        );

        let mut cli = SourceMap::new();
        cli.insert(
            "age_key_file",
            SettingValue::OptionPath(Some(std::path::PathBuf::from("/cli/key.txt"))),
        );

        let merged = Settings::merge_settings(&defaults, &env, &cli);

        // CLI should win
        assert_eq!(
            merged.age_key_file,
            Some(std::path::PathBuf::from("/cli/key.txt"))
        );
    }

    #[test]
    fn test_settings_merge_partial() {
        let defaults = GeneratedSettings {
            age_key_file: None,
            profile: "default".to_string(),
            shell_integration_output: "normal".to_string(),
        };

        let mut env = SourceMap::new();
        env.insert(
            "age_key_file",
            SettingValue::OptionPath(Some(std::path::PathBuf::from("/env/key.txt"))),
        );

        let cli = SourceMap::new();

        let merged = Settings::merge_settings(&defaults, &env, &cli);

        // Env should be used since CLI is empty
        assert_eq!(
            merged.age_key_file,
            Some(std::path::PathBuf::from("/env/key.txt"))
        );
        // Default profile should remain
        assert_eq!(merged.profile, "default");
    }

    #[test]
    fn test_expand_path_with_tilde() {
        // Test tilde expansion
        let expanded = Settings::expand_path("~/test/path");
        let home = dirs::home_dir().unwrap();
        assert_eq!(expanded, home.join("test/path"));

        // Test without tilde (should remain unchanged)
        let expanded = Settings::expand_path("/absolute/path");
        assert_eq!(expanded, std::path::PathBuf::from("/absolute/path"));
    }
}
