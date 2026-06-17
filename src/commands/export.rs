use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::shell;
use crate::temp_file_secrets::create_persistent_secret_file;
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
    /// POSIX shell format (export KEY=value)
    Shell,
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
        let resolved_secrets = crate::daemon::resolve_batch(
            cli,
            &config,
            &profile,
            &profile_secrets,
            crate::daemon::Purpose::Export,
            true,
        )
        .await?;

        // Build secrets map, preserving insertion order
        // For file-based secrets, create persistent temp files
        let mut secrets = IndexMap::new();
        for (key, value_opt) in resolved_secrets {
            if let Some(value) = value_opt {
                // Check if this secret should be file-based
                if let Some(secret_config) = profile_secrets.get(&key) {
                    if secret_config.as_file {
                        // Create a persistent temp file for this secret
                        match create_persistent_secret_file("fnox-export-", &key, &value) {
                            Ok(file_path) => {
                                secrets.insert(key, file_path);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to create temp file for secret '{}': {}",
                                    key,
                                    e
                                );
                                // Fall back to storing the value
                                secrets.insert(key, value);
                            }
                        }
                    } else {
                        // Regular secret - store value directly
                        secrets.insert(key, value);
                    }
                } else {
                    secrets.insert(key, value);
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
            ExportFormat::Shell => self.export_as_shell(&export_data),
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

        append_metadata_header(&mut output, data.metadata.as_ref());

        for (key, value) in &data.secrets {
            output.push_str(&format!("{}={}\n", key, dotenv_quote(value)));
        }

        Ok(output)
    }

    fn export_as_shell(&self, data: &ExportData) -> Result<String> {
        let mut output = String::new();

        append_metadata_header(&mut output, data.metadata.as_ref());

        for (key, value) in &data.secrets {
            output.push_str(&format!("export {}={}\n", key, shell::posix_quote(value)));
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

fn append_metadata_header(output: &mut String, metadata: Option<&ExportMetadata>) {
    if let Some(metadata) = metadata {
        output.push_str(&format!("# Exported from profile: {}\n", metadata.profile));
        output.push_str(&format!("# Exported at: {}\n", metadata.exported_at));
        output.push_str(&format!("# Total secrets: {}\n", metadata.total_secrets));
        output.push('\n');
    }
}

fn dotenv_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':'))
    {
        return value.to_string();
    }

    // Dotenv parsers treat `$` and backticks literally; use `--format shell`
    // for sourceable shell output.
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::dotenv_quote;

    #[test]
    fn dotenv_quote_leaves_simple_values_unquoted() {
        assert_eq!(dotenv_quote("kek"), "kek");
        assert_eq!(
            dotenv_quote("/tmp/fnox-export-FILE_SECRET-abc"),
            "/tmp/fnox-export-FILE_SECRET-abc"
        );
    }

    #[test]
    fn dotenv_quote_escapes_special_values() {
        assert_eq!(dotenv_quote("value with spaces"), "\"value with spaces\"");
        assert_eq!(dotenv_quote("it's \"fine\""), "\"it's \\\"fine\\\"\"");
        assert_eq!(dotenv_quote("a\nb\t$c`d"), "\"a\\nb\\t$c`d\"");
    }
}
