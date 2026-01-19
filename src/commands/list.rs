use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use crate::secret_resolver::resolve_secrets_batch;
use clap::Args;
use indexmap::IndexMap;
use tabled::settings::{
    Color, Format, Modify, Style, Width,
    object::{Columns, Rows},
};
use tabled::{Table, Tabled};

#[derive(Debug, Args)]
#[command(visible_aliases = ["ls", "secrets"])]
pub struct ListCommand {
    /// Show full provider keys without truncation
    #[arg(short, long)]
    pub full: bool,

    /// Show source file paths where secrets are defined
    #[arg(short, long)]
    pub sources: bool,

    /// Show secret values (if available)
    #[arg(short = 'V', long)]
    pub values: bool,

    /// Output secret keys for shell completion (one per line)
    #[arg(long, hide = true)]
    pub complete: bool,
}

#[derive(Debug, Tabled)]
struct SecretRow {
    #[tabled(rename = "Key")]
    key: String,
    #[tabled(rename = "Type")]
    source_type: String,
    #[tabled(rename = "Provider Key")]
    provider_key: String,
    #[tabled(rename = "Description")]
    description: String,
}

#[derive(Debug, Tabled)]
struct SecretRowWithSources {
    #[tabled(rename = "Key")]
    key: String,
    #[tabled(rename = "Type")]
    source_type: String,
    #[tabled(rename = "Source File")]
    source_file: String,
    #[tabled(rename = "Provider Key")]
    provider_key: String,
    #[tabled(rename = "Description")]
    description: String,
}

#[derive(Debug, Tabled)]
struct SecretRowWithValues {
    #[tabled(rename = "Key")]
    key: String,
    #[tabled(rename = "Type")]
    source_type: String,
    #[tabled(rename = "Provider Key")]
    provider_key: String,
    #[tabled(rename = "Description")]
    description: String,
    #[tabled(rename = "Value")]
    value: String,
}

#[derive(Debug, Tabled)]
struct SecretRowWithValuesAndSources {
    #[tabled(rename = "Key")]
    key: String,
    #[tabled(rename = "Type")]
    source_type: String,
    #[tabled(rename = "Source File")]
    source_file: String,
    #[tabled(rename = "Provider Key")]
    provider_key: String,
    #[tabled(rename = "Description")]
    description: String,
    #[tabled(rename = "Value")]
    value: String,
}

impl ListCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Listing secrets in profile '{}'", profile);

        // Get the profile secrets
        let profile_secrets = config.get_secrets(&profile)?;

        if profile_secrets.is_empty() {
            if !self.complete {
                println!("No secrets defined in profile '{}'", profile);
            }
            return Ok(());
        }

        // Preserve insertion order from IndexMap
        let keys: Vec<_> = profile_secrets.keys().collect();

        // Handle completion mode
        if self.complete {
            for key in keys {
                println!("{}", key);
            }
            return Ok(());
        }

        // Resolve secrets if values are requested
        let resolved_values = if self.values {
            Some(resolve_secrets_batch(&config, &profile, &profile_secrets).await?)
        } else {
            None
        };

        if self.values && self.sources {
            self.display_with_values_and_sources(
                &keys,
                &profile_secrets,
                resolved_values.as_ref().unwrap(),
            )?;
        } else if self.values {
            self.display_with_values(&keys, &profile_secrets, resolved_values.as_ref().unwrap())?;
        } else if self.sources {
            self.display_with_sources(&keys, &profile_secrets)?;
        } else {
            self.display_basic(&keys, &profile_secrets)?;
        }

        Ok(())
    }

    fn get_source_type_and_provider_key(
        &self,
        secret_config: &crate::config::SecretConfig,
    ) -> (String, String) {
        if let Some(provider) = secret_config.provider() {
            let pk = secret_config.value().unwrap_or("");
            let pk_display = if !self.full && pk.len() > 40 {
                format!("{}...", &pk[..37])
            } else {
                pk.to_string()
            };
            (format!("provider ({})", provider), pk_display)
        } else if secret_config.value().is_some() {
            ("stored value".to_string(), String::new())
        } else if secret_config.default.is_some() {
            ("default value".to_string(), String::new())
        } else {
            ("env var".to_string(), String::new())
        }
    }

    fn display_basic(
        &self,
        keys: &[&String],
        profile_secrets: &indexmap::IndexMap<String, crate::config::SecretConfig>,
    ) -> Result<()> {
        let mut rows = Vec::new();
        for key in keys {
            let secret_config = &profile_secrets[*key];
            let (source_type, provider_key_str) =
                self.get_source_type_and_provider_key(secret_config);
            let description_str = secret_config
                .description
                .as_deref()
                .unwrap_or("")
                .to_string();

            rows.push(SecretRow {
                key: (*key).clone(),
                source_type,
                provider_key: provider_key_str,
                description: description_str,
            });
        }

        self.display_table(rows)
    }

    fn display_with_sources(
        &self,
        keys: &[&String],
        profile_secrets: &indexmap::IndexMap<String, crate::config::SecretConfig>,
    ) -> Result<()> {
        let mut rows = Vec::new();
        for key in keys {
            let secret_config = &profile_secrets[*key];
            let (source_type, provider_key_str) =
                self.get_source_type_and_provider_key(secret_config);
            let description_str = secret_config
                .description
                .as_deref()
                .unwrap_or("")
                .to_string();
            let source_file = secret_config
                .source_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            rows.push(SecretRowWithSources {
                key: (*key).clone(),
                source_type,
                source_file,
                provider_key: provider_key_str,
                description: description_str,
            });
        }

        self.display_table(rows)
    }

    fn display_with_values(
        &self,
        keys: &[&String],
        profile_secrets: &indexmap::IndexMap<String, crate::config::SecretConfig>,
        resolved_values: &IndexMap<String, Option<String>>,
    ) -> Result<()> {
        let mut rows = Vec::new();
        for key in keys {
            let secret_config = &profile_secrets[*key];
            let (source_type, provider_key_str) =
                self.get_source_type_and_provider_key(secret_config);
            let description_str = secret_config
                .description
                .as_deref()
                .unwrap_or("")
                .to_string();

            // Use the resolved value if available, otherwise show placeholder
            let value_str = resolved_values
                .get(*key)
                .and_then(|v| v.as_ref())
                .cloned()
                .unwrap_or_else(|| "<not available>".to_string());

            rows.push(SecretRowWithValues {
                key: (*key).clone(),
                source_type,
                provider_key: provider_key_str,
                description: description_str,
                value: value_str,
            });
        }

        self.display_table(rows)
    }

    fn display_with_values_and_sources(
        &self,
        keys: &[&String],
        profile_secrets: &indexmap::IndexMap<String, crate::config::SecretConfig>,
        resolved_values: &IndexMap<String, Option<String>>,
    ) -> Result<()> {
        let mut rows = Vec::new();
        for key in keys {
            let secret_config = &profile_secrets[*key];
            let (source_type, provider_key_str) =
                self.get_source_type_and_provider_key(secret_config);
            let description_str = secret_config
                .description
                .as_deref()
                .unwrap_or("")
                .to_string();
            let source_file = secret_config
                .source_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            // Use the resolved value if available, otherwise show placeholder
            let value_str = resolved_values
                .get(*key)
                .and_then(|v| v.as_ref())
                .cloned()
                .unwrap_or_else(|| "<not available>".to_string());

            rows.push(SecretRowWithValuesAndSources {
                key: (*key).clone(),
                source_type,
                source_file,
                provider_key: provider_key_str,
                description: description_str,
                value: value_str,
            });
        }

        self.display_table(rows)
    }

    fn display_table<T: tabled::Tabled>(&self, rows: Vec<T>) -> Result<()> {
        let mut table = Table::new(rows);
        table.with(Style::empty());

        // Apply colors only if enabled
        if console::colors_enabled() {
            table.with(
                Modify::new(Rows::first())
                    .with(Color::FG_BRIGHT_BLUE)
                    .with(Format::content(|s| format!("\x1b[1m{}\x1b[0m", s))),
            );
        }

        if !self.full {
            // Apply width constraints for description and provider key columns
            table.with(Modify::new(Columns::last()).with(Width::wrap(40)));
        }

        println!("{}", table);
        Ok(())
    }
}
