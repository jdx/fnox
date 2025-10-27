use crate::commands::Cli;
use crate::config::{Config, IfMissing};
use crate::error::Result;
use crate::secret_resolver::resolve_secret;
use crate::settings::Settings;
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

        let mut secrets = IndexMap::new();

        for (key, secret_config) in &profile_secrets {
            // Use centralized secret resolver for consistent priority order
            match resolve_secret(
                &config,
                &profile,
                key,
                secret_config,
                cli.age_key_file.as_deref(),
            )
            .await
            {
                Ok(Some(value)) => {
                    secrets.insert(key.clone(), value);
                }
                Ok(None) => {
                    // Secret not found but if_missing allows it
                }
                Err(e) => {
                    // Provider error - respect if_missing to decide whether to fail or continue
                    // Priority: CLI flag > Env var > Secret-level > Top-level config > FNOX_IF_MISSING_DEFAULT > Default
                    let if_missing = Settings::try_get()
                        .ok()
                        .and_then(|s| {
                            // If Some(value), CLI or env var was explicitly set (highest priority)
                            s.if_missing.as_ref().map(|value| {
                                match value.to_lowercase().as_str() {
                                    "error" => IfMissing::Error,
                                    "warn" => IfMissing::Warn,
                                    "ignore" => IfMissing::Ignore,
                                    _ => IfMissing::Warn,
                                }
                            })
                        })
                        .or(secret_config.if_missing)
                        .or(config.if_missing)
                        .or_else(|| {
                            // Check FNOX_IF_MISSING_DEFAULT (via Settings) as fallback
                            Settings::try_get().ok().and_then(|s| {
                                s.if_missing_default
                                    .as_ref()
                                    .map(|value| match value.to_lowercase().as_str() {
                                        "error" => IfMissing::Error,
                                        "warn" => IfMissing::Warn,
                                        "ignore" => IfMissing::Ignore,
                                        _ => {
                                            eprintln!(
                                                "Warning: Invalid FNOX_IF_MISSING_DEFAULT value '{}', using 'warn'",
                                                value
                                            );
                                            IfMissing::Warn
                                        }
                                    })
                            })
                        })
                        .unwrap_or(IfMissing::Warn);

                    match if_missing {
                        IfMissing::Error => {
                            tracing::error!("Error resolving secret '{}': {}", key, e);
                            return Err(e);
                        }
                        IfMissing::Warn => {
                            tracing::warn!("Error resolving secret '{}': {}", key, e);
                        }
                        IfMissing::Ignore => {
                            // Silently skip
                        }
                    }
                }
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
