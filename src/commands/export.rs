use crate::commands::Cli;
use crate::config::{Config, SecretConfig};
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::get_provider;
use clap::{Args, ValueEnum};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use strum::{Display, EnumString, VariantNames};

/// Supported export formats
#[derive(Debug, Clone, Copy, ValueEnum, Display, EnumString, VariantNames)]
#[strum(serialize_all = "lowercase")]
pub enum ExportFormat {
    /// Environment variable format (KEY=value)
    Env,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// TOML format
    Toml,
}

/// Export secrets in various formats
#[derive(Args)]
#[command(visible_aliases = ["ex"])]
pub struct ExportCommand {
    /// Export format
    #[arg(short, long, default_value = "env", value_enum)]
    format: ExportFormat,

    /// Output file (default: stdout)
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct ExportData {
    secrets: IndexMap<String, String>,
    metadata: Option<ExportMetadata>,
}

#[derive(Serialize, Deserialize)]
struct ExportMetadata {
    profile: String,
    exported_at: String,
    total_secrets: usize,
}

impl ExportCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Exporting secrets from profile '{}'", profile);

        let profile_secrets = config.get_secrets(&profile)?;
        let providers = config.get_providers(&profile);

        let mut secrets = IndexMap::new();

        for (key, secret_config) in profile_secrets {
            let value = self
                .resolve_secret_value(key, secret_config, &providers)
                .await?;
            if let Some(value) = value {
                secrets.insert(key.clone(), value);
            }
        }

        let metadata = Some(ExportMetadata {
            profile: profile.clone(),
            exported_at: chrono::Utc::now().to_rfc3339(),
            total_secrets: secrets.len(),
        });

        let export_data = ExportData { secrets, metadata };

        let output = match self.format {
            ExportFormat::Env => self.export_as_env(&export_data),
            ExportFormat::Json => self.export_as_json(&export_data),
            ExportFormat::Yaml => self.export_as_yaml(&export_data),
            ExportFormat::Toml => self.export_as_toml(&export_data),
        }?;

        match &self.output {
            Some(path) => {
                std::fs::write(path, output).map_err(|e| {
                    miette::miette!("Failed to write to file {}: {}", path.display(), e)
                })?;
                println!("Secrets exported to: {}", path.display());
            }
            None => {
                print!("{}", output);
            }
        }

        Ok(())
    }

    async fn resolve_secret_value(
        &self,
        key: &str,
        secret_config: &SecretConfig,
        providers: &IndexMap<String, crate::config::ProviderConfig>,
    ) -> Result<Option<String>> {
        // Check provider first
        if let Some(ref provider_name) = secret_config.provider {
            let provider_config = providers.get(provider_name).ok_or_else(|| {
                miette::miette!(
                    "Provider '{}' not found for secret '{}'",
                    provider_name,
                    key
                )
            })?;

            if let Some(provider_value) = &secret_config.value {
                let provider = get_provider(provider_config)?;
                let value = provider.get_secret(provider_value, None).await?;
                return Ok(Some(value));
            } else {
                tracing::warn!(
                    "Provider '{}' specified for secret '{}' but no value provided",
                    provider_name,
                    key
                );
                return Ok(None);
            }
        }

        // Check direct value
        if let Some(value) = &secret_config.value {
            return Ok(Some(value.clone()));
        }

        // Check current environment variable
        if let Ok(env_value) = env::var(key) {
            return Ok(Some(env_value));
        }

        // Use default value
        if let Some(default) = &secret_config.default {
            return Ok(Some(default.clone()));
        }

        // Handle missing secrets
        match secret_config.if_missing {
            Some(crate::config::IfMissing::Error) => Err(FnoxError::Config(format!(
                "Secret '{}' not found and no default provided",
                key
            ))),
            Some(crate::config::IfMissing::Warn) | None => {
                // Default to warn when if_missing is not specified
                eprintln!(
                    "Warning: Secret '{}' not found and no default provided",
                    key
                );
                Ok(None)
            }
            Some(crate::config::IfMissing::Ignore) => Ok(None),
        }
    }

    fn export_as_env(&self, data: &ExportData) -> Result<String> {
        let mut output = String::new();

        if let Some(metadata) = &data.metadata {
            output.push_str(&format!("# Exported from profile: {}\n", metadata.profile));
            output.push_str(&format!("# Exported at: {}\n", metadata.exported_at));
            output.push_str(&format!("# Total secrets: {}\n", metadata.total_secrets));
            output.push('\n');
        }

        for (key, value) in &data.secrets {
            output.push_str(&format!("export {}='{}'\n", key, value));
        }

        Ok(output)
    }

    fn export_as_json(&self, data: &ExportData) -> Result<String> {
        Ok(serde_json::to_string_pretty(data)
            .map_err(|e| miette::miette!("JSON serialization error: {}", e))?)
    }

    fn export_as_yaml(&self, data: &ExportData) -> Result<String> {
        Ok(serde_yaml::to_string(data)
            .map_err(|e| miette::miette!("YAML serialization error: {}", e))?)
    }

    fn export_as_toml(&self, data: &ExportData) -> Result<String> {
        Ok(toml_edit::ser::to_string_pretty(data)
            .map_err(|e| miette::miette!("TOML serialization error: {}", e))?)
    }
}
