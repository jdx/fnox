use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use clap::{Args, ValueEnum};
use regex::Regex;
use std::io::{self, Read};
use std::{collections::HashMap, path::PathBuf};
use strum::{Display, EnumString, VariantNames};

/// Supported import formats
#[derive(Debug, Clone, Copy, ValueEnum, Display, EnumString, VariantNames)]
#[strum(serialize_all = "lowercase")]
pub enum ImportFormat {
    /// Environment variable format (KEY=value)
    Env,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// TOML format
    Toml,
}

/// Import secrets from various sources
#[derive(Args)]
#[command(visible_aliases = ["im"])]
pub struct ImportCommand {
    /// Import source format
    #[arg(default_value = "env", value_enum)]
    format: ImportFormat,

    /// Skip confirmation prompts
    #[arg(short, long)]
    force: bool,

    /// Import to the global config file (~/.config/fnox/config.toml)
    #[arg(short = 'g', long)]
    global: bool,

    /// Source file or path to import from (default: stdin)
    #[arg(short = 'i', long)]
    input: Option<PathBuf>,

    /// Provider to use for encrypting/storing imported secrets (required)
    #[arg(short = 'p', long)]
    provider: String,

    /// Only import matching secrets (regex pattern)
    #[arg(long)]
    filter: Option<String>,

    /// Prefix to add to imported secret names
    #[arg(long)]
    prefix: Option<String>,
}

impl ImportCommand {
    pub async fn run(&self, cli: &Cli, merged_config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!(
            "Importing secrets in {} format into profile '{}'",
            self.format,
            profile
        );

        let input = self.read_input()?;
        let mut secrets = self.parse_input(&input)?;

        // When importing from stdin, --force is required because stdin is consumed
        // by read_input() and won't be available for the confirmation prompt
        if self.input.is_none() && !self.force {
            return Err(miette::miette!(
                "When importing from stdin, the --force flag is required\n\n\
                This is because stdin is consumed during import and cannot be used \
                for the confirmation prompt.\n\n\
                Use: fnox import --force < input.env\n\
                Or:  cat input.env | fnox import --force"
            )
            .into());
        }

        // Apply filter if specified
        if let Some(ref filter) = self.filter {
            let regex = Regex::new(filter)
                .map_err(|e| miette::miette!("Invalid regex filter '{}': {}", filter, e))?;
            secrets.retain(|key, _| regex.is_match(key));
        }

        // Apply prefix if specified
        if let Some(ref prefix) = self.prefix {
            let mut prefixed_secrets = HashMap::new();
            for (key, value) in secrets {
                let prefixed_key = format!("{}{}", prefix, key);
                prefixed_secrets.insert(prefixed_key, value);
            }
            secrets = prefixed_secrets;
        }

        if secrets.is_empty() {
            println!("No secrets to import");
            return Ok(());
        }

        // Confirm import unless forced
        if !self.force {
            println!(
                "\nReady to import {} secrets into profile '{}':",
                secrets.len(),
                profile
            );
            for key in secrets.keys().take(10) {
                println!("  {}", key);
            }
            if secrets.len() > 10 {
                println!("  ... and {} more", secrets.len() - 10);
            }

            println!("\nContinue? [y/N]");
            let mut response = String::new();
            io::stdin()
                .read_line(&mut response)
                .map_err(|e| miette::miette!("Failed to read response: {}", e))?;

            if !response.trim().to_lowercase().starts_with('y') {
                println!("Import cancelled");
                return Ok(());
            }
        }

        // Verify provider exists (use merged config to find providers from any source)
        let providers = merged_config.get_providers(&profile);
        let provider_config = providers.get(&self.provider).ok_or_else(|| {
            miette::miette!(
                "Provider '{}' not found in profile '{}'. Available providers: {}",
                self.provider,
                profile,
                providers
                    .keys()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

        // Get provider and check its capabilities
        let provider = crate::providers::get_provider(provider_config)?;
        let capabilities = provider.capabilities();

        if capabilities.is_empty() {
            return Err(miette::miette!(
                "Provider '{}' has no capabilities defined",
                self.provider
            )
            .into());
        }

        let is_encryption_provider =
            capabilities.contains(&crate::providers::ProviderCapability::Encryption);
        let is_remote_storage_provider =
            capabilities.contains(&crate::providers::ProviderCapability::RemoteStorage);

        // Determine the target config file path
        let target_path = if self.global {
            let global_path = Config::global_config_path();
            // Create parent directory if it doesn't exist
            if let Some(parent) = global_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    miette::miette!(
                        "Failed to create config directory '{}': {}",
                        parent.display(),
                        e
                    )
                })?;
            }
            global_path
        } else {
            cli.config.clone()
        };

        // Load only the target config file (not merged) for modification
        let mut target_config = if target_path.exists() {
            Config::load(&target_path)?
        } else {
            Config::new()
        };

        // Process and encrypt/store each secret into the target config
        {
            let profile_secrets = target_config.get_secrets_mut(&profile);
            let total_secrets = secrets.len();

            for (key, value) in secrets {
                let secret_config = profile_secrets.entry(key.clone()).or_default();

                // Set the provider
                secret_config.provider = Some(self.provider.clone());

                // Handle encryption or remote storage based on provider capabilities
                if is_encryption_provider {
                    // Encrypt the value
                    match provider.encrypt(&value).await {
                        Ok(encrypted) => {
                            secret_config.value = Some(encrypted);
                        }
                        Err(e) => {
                            return Err(miette::miette!(
                                "Failed to encrypt secret '{}' with provider '{}': {}",
                                key,
                                self.provider,
                                e
                            )
                            .into());
                        }
                    }
                } else if is_remote_storage_provider {
                    return Err(miette::miette!(
                        "Remote storage providers are not yet supported for import. Use an encryption provider like 'age' instead."
                    )
                    .into());
                } else {
                    return Err(miette::miette!(
                        "Provider '{}' does not support encryption or remote storage",
                        self.provider
                    )
                    .into());
                }
            }

            let global_suffix = if self.global { " (global)" } else { "" };
            println!(
                "✓ Imported {} secrets into profile '{}' using provider '{}'{}",
                total_secrets, profile, self.provider, global_suffix
            );
        }

        // Save only the target config
        target_config.save(&target_path)?;

        Ok(())
    }

    fn read_input(&self) -> Result<String> {
        if let Some(ref input_path) = self.input {
            // Read from specified file
            let input = std::fs::read_to_string(input_path).map_err(|e| {
                miette::miette!(
                    "Failed to read input file '{}': {}",
                    input_path.display(),
                    e
                )
            })?;
            Ok(input)
        } else {
            // Read from stdin
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .map_err(|e| miette::miette!("Failed to read from stdin: {}", e))?;
            Ok(input)
        }
    }

    fn parse_input(&self, input: &str) -> Result<HashMap<String, String>> {
        match self.format {
            ImportFormat::Env => self.parse_env(input),
            ImportFormat::Json => self.parse_json(input),
            ImportFormat::Yaml => self.parse_yaml(input),
            ImportFormat::Toml => self.parse_toml(input),
        }
    }

    fn parse_env(&self, input: &str) -> Result<HashMap<String, String>> {
        let mut secrets = HashMap::new();

        for line in input.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse export statements and simple KEY=VALUE
            if let Some(export_key_value) = line.strip_prefix("export ") {
                self.parse_key_value(export_key_value, &mut secrets)?;
            } else {
                self.parse_key_value(line, &mut secrets)?;
            }
        }

        Ok(secrets)
    }

    fn parse_key_value(&self, line: &str, secrets: &mut HashMap<String, String>) -> Result<()> {
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();

            // Handle quoted values
            let value = if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value[1..value.len() - 1].to_string()
            } else {
                value.to_string()
            };

            if !key.is_empty() {
                secrets.insert(key.to_string(), value);
            }
        }
        Ok(())
    }

    fn parse_json(&self, input: &str) -> Result<HashMap<String, String>> {
        let data: serde_json::Value = serde_json::from_str(input)
            .map_err(|e| miette::miette!("Failed to parse JSON: {}", e))?;

        self.extract_string_values(&data)
    }

    fn parse_yaml(&self, input: &str) -> Result<HashMap<String, String>> {
        let data: serde_yaml::Value = serde_yaml::from_str(input)
            .map_err(|e| miette::miette!("Failed to parse YAML: {}", e))?;

        self.extract_string_values(&data)
    }

    fn parse_toml(&self, input: &str) -> Result<HashMap<String, String>> {
        let data: serde_json::Value = toml_edit::de::from_str(input)
            .map_err(|e| miette::miette!("Failed to parse TOML: {}", e))?;

        self.extract_string_values(&data)
    }

    fn extract_string_values<V>(&self, data: &V) -> Result<HashMap<String, String>>
    where
        V: serde::Serialize,
    {
        let json_value = serde_json::to_value(data)
            .map_err(|e| miette::miette!("Failed to convert data: {}", e))?;

        let mut secrets = HashMap::new();

        if let serde_json::Value::Object(map) = json_value {
            for (key, value) in map {
                match value {
                    serde_json::Value::String(s) => {
                        secrets.insert(key, s);
                    }
                    serde_json::Value::Null
                    | serde_json::Value::Bool(_)
                    | serde_json::Value::Number(_) => {
                        secrets.insert(key, value.to_string());
                    }
                    _ => {
                        tracing::warn!("Skipping non-string value for key '{}'", key);
                    }
                }
            }
        }

        Ok(secrets)
    }
}
