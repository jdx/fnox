use crate::env;
use crate::error::{FnoxError, Result};
use clap::ValueEnum;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use strum::VariantNames;

// Re-export ProviderConfig from providers module
pub use crate::providers::ProviderConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub default_provider: Option<String>,

    /// Default profile secrets (top level)
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub secrets: IndexMap<String, SecretConfig>,

    /// Named profiles
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub profiles: IndexMap<String, ProfileConfig>,

    /// Age encryption key file path (optional, can also be set via env var or CLI flag)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_key_file: Option<PathBuf>,

    /// Track which config file each provider came from (not serialized)
    #[serde(skip)]
    pub provider_sources: HashMap<String, PathBuf>,

    /// Track which config file each secret came from (not serialized)
    #[serde(skip)]
    pub secret_sources: HashMap<String, PathBuf>,
}

/// Configuration for a single secret
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub provider: Option<String>,

    /// Value for the provider (secret name, encrypted blob, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// Path to the config file where this secret was defined (not serialized)
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
}

/// Configuration for a profile
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// Provider configurations for this profile
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub providers: IndexMap<String, ProviderConfig>,

    /// Default provider name for this profile
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<String>,

    /// Secrets for this profile
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub secrets: IndexMap<String, SecretConfig>,

    /// Track which config file each provider came from (not serialized)
    #[serde(skip)]
    pub provider_sources: HashMap<String, PathBuf>,

    /// Track which config file each secret came from (not serialized)
    #[serde(skip)]
    pub secret_sources: HashMap<String, PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ValueEnum, VariantNames)]
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

        // If the path is exactly "fnox.toml" (default), use recursive loading
        if path_ref == Path::new("fnox.toml") {
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
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| FnoxError::Config(format!("Failed to read config file: {}", e)))?;

        let mut config: Config = toml_edit::de::from_str(&content)?;

        // Set source paths for all secrets and providers
        config.set_source_paths(path);

        Ok(config)
    }

    /// Load configuration with recursive directory search and merging
    pub fn load_with_recursion<P: AsRef<Path>>(_start_path: P) -> Result<Self> {
        // Start from current working directory and search upwards
        let current_dir = env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {}", e)))?;

        match Self::load_recursive(&current_dir, false, false) {
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
    fn load_recursive(dir: &Path, _from_parent: bool, found_any: bool) -> Result<(Self, bool)> {
        let config_path = dir.join("fnox.toml");
        let (mut config, mut found) = if config_path.exists() {
            (Self::load(&config_path)?, true)
        } else {
            (Self::new(), found_any)
        };

        // If this config marks root, stop recursion
        if config.root {
            // Load imports if any
            for import_path in &config.import.clone() {
                let import_config = Self::load_import(import_path, dir)?;
                config = Self::merge_configs(import_config, config)?;
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
            let (parent_config, parent_found) = Self::load_recursive(parent_dir, true, found)?;
            config = Self::merge_configs(parent_config, config)?;
            found = found || parent_found;
        }

        Ok((config, found))
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
            } else {
                merged.profiles.insert(name, profile);
            }
        }

        Ok(merged)
    }

    /// Save configuration to a file
    /// Uses toml_edit to preserve insertion order from IndexMap
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // Clone and clean up empty profiles before saving
        let mut clean_config = self.clone();
        clean_config
            .profiles
            .retain(|_, profile| !profile.is_empty());

        let content = toml_edit::ser::to_string_pretty(&clean_config)?;
        fs::write(path.as_ref(), content)
            .map_err(|e| FnoxError::Config(format!("Failed to write config file: {}", e)))?;
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
            provider_sources: HashMap::new(),
            secret_sources: HashMap::new(),
        }
    }

    /// Get the profile to use (from flag or env var, defaulting to "default")
    pub fn get_profile(profile_flag: Option<&str>) -> String {
        profile_flag
            .map(String::from)
            .or_else(|| (*env::FNOX_PROFILE).clone())
            .unwrap_or_else(|| "default".to_string())
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
    /// with profile secrets taking precedence
    pub fn get_secrets(&self, profile: &str) -> Result<IndexMap<String, SecretConfig>> {
        if profile == "default" {
            Ok(self.secrets.clone())
        } else {
            // Start with top-level secrets as base
            let mut secrets = self.secrets.clone();

            // Get profile-specific secrets and merge/override
            if let Some(profile_config) = self.profiles.get(profile) {
                // Profile-specific secrets override top-level ones
                secrets.extend(profile_config.secrets.clone());
                Ok(secrets)
            } else {
                let available_profiles: Vec<String> = self.profiles.keys().cloned().collect();
                Err(FnoxError::ProfileNotFound {
                    profile: profile.to_string(),
                    available_profiles,
                })
            }
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
            && let Some(ref default_provider) = profile_config.default_provider
        {
            // Validate that the default provider exists
            if !providers.contains_key(default_provider) {
                return Err(FnoxError::Config(format!(
                    "Default provider '{}' not found in profile '{}'",
                    default_provider, profile
                )));
            }
            return Ok(Some(default_provider.clone()));
        }

        // Check for global default provider (for default profile or as fallback)
        if let Some(ref default_provider) = self.default_provider {
            // Validate that the default provider exists
            if !providers.contains_key(default_provider) {
                return Err(FnoxError::Config(format!(
                    "Default provider '{}' not found in configuration",
                    default_provider
                )));
            }
            return Ok(Some(default_provider.clone()));
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
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // If root=true and no providers AND no secrets, that's OK (empty config)
        if self.root
            && self.providers.is_empty()
            && self.profiles.is_empty()
            && self.secrets.is_empty()
        {
            return Ok(());
        }

        // Check that there's at least one provider if there are any secrets
        if self.providers.is_empty() && self.profiles.is_empty() && !self.secrets.is_empty() {
            return Err(FnoxError::Config(
                "No providers configured. Add at least one provider to fnox.toml".to_string(),
            ));
        }

        // If default_provider is set, validate it exists
        if let Some(ref default_provider) = self.default_provider
            && !self.providers.contains_key(default_provider)
        {
            return Err(FnoxError::Config(format!(
                "Default provider '{}' not found in configuration",
                default_provider
            )));
        }

        // Validate each profile
        for (profile_name, profile_config) in &self.profiles {
            let providers = self.get_providers(profile_name);

            // Each profile must have at least one provider (inherited or its own), unless root=true
            if providers.is_empty() && !self.root {
                return Err(FnoxError::Config(format!(
                    "Profile '{}' has no providers configured",
                    profile_name
                )));
            }

            // If profile has default_provider set, validate it exists
            if let Some(ref default_provider) = profile_config.default_provider
                && !providers.contains_key(default_provider)
            {
                return Err(FnoxError::Config(format!(
                    "Default provider '{}' not found in profile '{}'",
                    default_provider, profile_name
                )));
            }
        }

        Ok(())
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

    /// Check if this secret has any value (provider, value, or default)
    pub fn has_value(&self) -> bool {
        self.provider.is_some() || self.value.is_some() || self.default.is_some()
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
        }
    }

    /// Check if the profile is effectively empty (no serializable content)
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty() && self.secrets.is_empty() && self.default_provider.is_none()
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
        secret.value = Some("test-value".to_string());
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
