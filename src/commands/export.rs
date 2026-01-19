use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::secret_resolver::resolve_secrets_batch;
use clap::{Args, ValueEnum};
use console;
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

    /// Show what would be exported without writing to file
    #[arg(short = 'n', long)]
    dry_run: bool,

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

        // Resolve secrets using batch resolution for better performance
        let resolved_secrets = resolve_secrets_batch(&config, &profile, &profile_secrets).await?;

        // Build secrets map, preserving insertion order
        let mut secrets = IndexMap::new();
        for (key, value) in resolved_secrets {
            if let Some(value) = value {
                secrets.insert(key, value);
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
                if self.dry_run {
                    let dry_run_label = console::style("[dry-run]").yellow().bold();
                    let styled_path = console::style(path.display()).cyan();
                    println!(
                        "{dry_run_label} Would export {} secrets to {styled_path} in {} format:",
                        export_data.secrets.len(),
                        format!("{:?}", self.format).to_lowercase()
                    );
                    for key in export_data.secrets.keys() {
                        println!("  {}", console::style(key).dim());
                    }
                } else {
                    let path = path.to_path_buf();
                    std::fs::write(&path, &output)
                        .map_err(|e| FnoxError::ExportWriteFailed { path, source: e })?;
                    println!(
                        "Secrets exported to: {}",
                        self.output.as_ref().unwrap().display()
                    );
                }
            }
            None => {
                // When outputting to stdout, dry-run just outputs normally
                // (there's nothing to "protect" since we're not writing a file)
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
        Ok(serde_json::to_string_pretty(data)?)
    }

    fn export_as_yaml(&self, data: &ExportData) -> Result<String> {
        Ok(serde_yaml::to_string(data)?)
    }

    fn export_as_toml(&self, data: &ExportData) -> Result<String> {
        toml_edit::ser::to_string_pretty(data).map_err(|source| FnoxError::Toml { source })
    }
}
