use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use clap::{Args, ValueEnum};
use console;
use miette::{NamedSource, SourceSpan};
use regex::Regex;
use std::io::{self, Read};
use std::sync::Arc;
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

    /// Show what would be imported without making changes
    #[arg(short = 'n', long)]
    dry_run: bool,

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

        // When importing from stdin, --force or --dry-run is required because stdin is consumed
        // by read_input() and won't be available for the confirmation prompt
        // (dry-run doesn't need confirmation since it doesn't modify anything)
        if self.input.is_none() && !self.force && !self.dry_run {
            return Err(FnoxError::ImportStdinRequiresForce);
        }

        // Apply filter if specified
        if let Some(ref filter) = self.filter {
            let regex = Regex::new(filter).map_err(|e| FnoxError::InvalidRegexFilter {
                pattern: filter.clone(),
                details: e.to_string(),
            })?;
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

        // Verify provider exists (use merged config to find providers from any source)
        let providers = merged_config.get_providers(&profile);
        let provider_config =
            providers
                .get(&self.provider)
                .ok_or_else(|| FnoxError::ProviderNotConfigured {
                    provider: self.provider.clone(),
                    profile: profile.to_string(),
                    config_path: None,
                    suggestion: None,
                })?;

        // Get provider and validate capabilities (needed for both dry-run and actual import)
        let provider = crate::providers::get_provider_resolved(
            &merged_config,
            &profile,
            &self.provider,
            provider_config,
        )
        .await?;
        let capabilities = provider.capabilities();
        let is_encryption_provider =
            capabilities.contains(&crate::providers::ProviderCapability::Encryption);
        let is_remote_storage_provider =
            capabilities.contains(&crate::providers::ProviderCapability::RemoteStorage);

        // Validate that provider supports import (encryption capability required)
        if !is_encryption_provider {
            if is_remote_storage_provider {
                return Err(FnoxError::ImportProviderUnsupported {
                    provider: self.provider.clone(),
                    help: "Remote storage providers are not yet supported for import. Use an encryption provider like 'age' instead.".to_string(),
                });
            } else {
                return Err(FnoxError::ImportProviderUnsupported {
                    provider: self.provider.clone(),
                    help: "Provider does not support encryption or remote storage".to_string(),
                });
            }
        }

        // In dry-run mode, show what would be imported and exit
        // (provider and capability validation above ensures dry-run fails on invalid provider)
        if self.dry_run {
            let dry_run_label = console::style("[dry-run]").yellow().bold();
            let styled_profile = console::style(&profile).magenta();
            let styled_provider = console::style(&self.provider).green();
            let global_suffix = if self.global { " (global)" } else { "" };

            println!(
                "{dry_run_label} Would import {} secrets into profile {styled_profile} using provider {styled_provider}{global_suffix}:",
                secrets.len()
            );
            for key in secrets.keys() {
                println!("  {}", console::style(key).cyan());
            }
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
                .map_err(|e| FnoxError::StdinReadFailed { source: e })?;

            if !response.trim().to_lowercase().starts_with('y') {
                println!("Import cancelled");
                return Ok(());
            }
        }

        // Determine the target config file path
        let target_path = if self.global {
            let global_path = Config::global_config_path();
            // Create parent directory if it doesn't exist
            if let Some(parent) = global_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| FnoxError::CreateDirFailed {
                    path: parent.to_path_buf(),
                    source: e,
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
                secret_config.set_provider(Some(self.provider.clone()));

                // Encrypt the value (provider already validated as encryption provider)
                match provider.encrypt(&value).await {
                    Ok(encrypted) => {
                        secret_config.set_value(Some(encrypted));
                    }
                    Err(e) => {
                        return Err(FnoxError::ImportEncryptionFailed {
                            key: key.clone(),
                            provider: self.provider.clone(),
                            details: e.to_string(),
                        });
                    }
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
            let input =
                std::fs::read_to_string(input_path).map_err(|e| FnoxError::ImportReadFailed {
                    path: input_path.clone(),
                    source: e,
                })?;
            Ok(input)
        } else {
            // Read from stdin
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .map_err(|source| FnoxError::StdinReadFailed { source })?;
            Ok(input)
        }
    }

    fn parse_input(&self, input: &str) -> Result<HashMap<String, String>> {
        let source_name = self
            .input
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<stdin>".to_string());

        match self.format {
            ImportFormat::Env => self.parse_env(input),
            ImportFormat::Json => self.parse_json(input, &source_name),
            ImportFormat::Yaml => self.parse_yaml(input, &source_name),
            ImportFormat::Toml => self.parse_toml(input, &source_name),
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

    fn parse_json(&self, input: &str, source_name: &str) -> Result<HashMap<String, String>> {
        let data: serde_json::Value = serde_json::from_str(input).map_err(|e| {
            // serde_json provides line and column
            let offset = self.offset_from_line_col(input, e.line(), e.column());
            FnoxError::ImportParseErrorWithSource {
                format: "JSON".to_string(),
                details: e.to_string(),
                src: Arc::new(NamedSource::new(source_name, Arc::new(input.to_string()))),
                span: SourceSpan::new(offset.into(), 1usize),
            }
        })?;
        self.extract_string_values(&data)
    }

    fn parse_yaml(&self, input: &str, source_name: &str) -> Result<HashMap<String, String>> {
        let data: serde_yaml::Value = serde_yaml::from_str(input).map_err(|e| {
            // serde_yaml provides location via e.location()
            // Note: serde_yaml uses 0-indexed line/column, so we add 1 for our 1-indexed function
            if let Some(loc) = e.location() {
                let offset = self.offset_from_line_col(input, loc.line() + 1, loc.column() + 1);
                FnoxError::ImportParseErrorWithSource {
                    format: "YAML".to_string(),
                    details: e.to_string(),
                    src: Arc::new(NamedSource::new(source_name, Arc::new(input.to_string()))),
                    span: SourceSpan::new(offset.into(), 1usize),
                }
            } else {
                FnoxError::Config(format!("Failed to parse YAML: {}", e))
            }
        })?;
        self.extract_string_values(&data)
    }

    fn parse_toml(&self, input: &str, source_name: &str) -> Result<HashMap<String, String>> {
        let data: serde_json::Value = toml_edit::de::from_str(input).map_err(|e| {
            // toml_edit provides span via e.span()
            if let Some(span) = e.span() {
                FnoxError::ImportParseErrorWithSource {
                    format: "TOML".to_string(),
                    details: e.to_string(),
                    src: Arc::new(NamedSource::new(source_name, Arc::new(input.to_string()))),
                    span: SourceSpan::new(span.start.into(), span.end - span.start),
                }
            } else {
                FnoxError::Config(format!("Failed to parse TOML: {}", e))
            }
        })?;
        self.extract_string_values(&data)
    }

    /// Convert line/column (1-indexed) to byte offset for miette source spans.
    ///
    /// Handles both LF and CRLF line endings (CRLF is handled because we detect
    /// line boundaries at '\n', and '\r' is just part of line content).
    /// The column is treated as a character count, which is converted to the
    /// correct byte offset for multi-byte UTF-8.
    ///
    /// Note: serde_json may return line=0, col=0 for certain errors (type mismatches,
    /// custom errors) where position info isn't available. We return 0 in that case.
    fn offset_from_line_col(&self, input: &str, line: usize, col: usize) -> usize {
        // Handle invalid 0-indexed values (serde_json can return 0,0 for some errors)
        if line == 0 || col == 0 {
            return 0;
        }

        let mut current_line = 1;
        let mut line_start_byte = 0;

        // Find the byte offset of the target line by scanning for newlines
        for (byte_idx, c) in input.char_indices() {
            if current_line == line {
                // Found the start of target line
                line_start_byte = byte_idx;
                break;
            }
            if c == '\n' {
                current_line += 1;
                // Set line_start_byte to byte after newline for next iteration
                line_start_byte = byte_idx + 1;
            }
        }

        // If requested line is beyond the file, return end of input
        if current_line < line {
            return input.len();
        }

        // Defensive: clamp line_start_byte to input length
        // (should not happen with current logic, but guards against edge cases)
        let line_start_byte = line_start_byte.min(input.len());

        // Now count characters from line_start to find the column byte offset
        // col is 1-indexed, so we want to skip (col - 1) characters
        let chars_to_skip = col.saturating_sub(1);
        let line_slice = &input[line_start_byte..];

        line_slice
            .char_indices()
            .nth(chars_to_skip)
            .map(|(byte_offset, _)| line_start_byte + byte_offset)
            .unwrap_or(input.len())
    }

    fn extract_string_values<V>(&self, data: &V) -> Result<HashMap<String, String>>
    where
        V: serde::Serialize,
    {
        let json_value = serde_json::to_value(data)?;

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
