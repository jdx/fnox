use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::shell;
use crate::suggest::{find_similar, format_suggestions};
use crate::temp_file_secrets::create_persistent_secret_file;
use console;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use strum::{Display, EnumString, VariantNames};

/// Supported export formats
#[derive(Debug, Clone, Copy, usage_rs::ValueEnum, Display, EnumString, VariantNames)]
#[strum(serialize_all = "lowercase")]
pub enum ExportFormat {
    /// dotenv lines (`KEY=value`), quoted when needed
    Env,
    /// `export KEY=value` lines for POSIX shells
    Shell,
    /// JSON object with `secrets` and `metadata`
    Json,
    /// YAML document with `secrets` and `metadata`
    Yaml,
    /// TOML document with `secrets` and `metadata`
    Toml,
}

/// Print or write resolved secrets as env, shell, JSON, YAML, or TOML
///
/// Resolves the active profile's secrets and prints them in the chosen format,
/// or writes them to `--output`. By default only secrets with `env = true` are
/// included, matching shell integration; `--all` adds `env = "exec"` and
/// `env = false` secrets. An `as_file` secret is exported as the path of a
/// temporary file that holds its value.
///
/// Name one or more KEYs to export only those secrets. Only the named secrets
/// are resolved, so other secrets cost no provider calls or auth prompts.
/// Naming a key includes it whatever its `env` setting, so `--all` is not
/// needed. An unknown key is an error.
///
/// JSON, YAML, and TOML put the values in a `secrets` object, which
/// `fnox import` reads back. The output contains real values, and `--output`
/// creates the file with your default permissions, so set a restrictive umask
/// first.
#[derive(usage_rs::Args)]
#[usage(alias("ex"))]
#[usage(
    example("fnox export", header = "Print dotenv lines"),
    example("fnox export --format json", header = "Print JSON"),
    example(
        "fnox export --format json DATABASE_URL API_KEY",
        header = "Export only some secrets"
    ),
    example(
        "eval \"$(fnox export --format shell)\"",
        header = "Load secrets into the current shell"
    ),
    example(
        "(umask 077 && fnox export -o .env)",
        header = "Write a private .env file"
    ),
    after_long_help = "See also:\n- Import and export: https://fnox.jdx.dev/guide/import-export"
)]
pub struct ExportCommand {
    /// Secrets to export; all eligible secrets when omitted
    #[usage(arg)]
    key: Vec<String>,

    /// Output format
    #[usage(short, long, default = "env", value_enum)]
    format: ExportFormat,

    /// With `--output`, list the keys instead of writing the file
    ///
    /// Has no effect on output to stdout, which still contains the values.
    #[usage(short = 'n', long)]
    dry_run: bool,

    /// Write to this file instead of stdout
    #[usage(short = 'o', long)]
    output: Option<PathBuf>,

    /// Include secrets with `env = false` or `env = "exec"`
    #[usage(long)]
    all: bool,

    /// Start env and shell output with comments naming the profile, time, and count
    #[usage(long)]
    header: bool,
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
        let profile = Config::get_profiles(cli.profile.as_slice());
        tracing::debug!(
            "Exporting secrets from profiles '{}'",
            Config::display_profiles(&profile)
        );

        let mut profile_secrets = config.get_secrets(&profile)?;

        // Export is a shell-injection surface, so exclude secrets not meant for
        // the shell unless --all is passed. Filtering before resolution avoids
        // auth prompts for hidden secrets.
        if !self.key.is_empty() {
            // Naming a key is explicit opt-in, so it bypasses the env filter.
            for key in &self.key {
                if !profile_secrets.contains_key(key) {
                    let available_keys: Vec<_> =
                        profile_secrets.keys().map(|s| s.as_str()).collect();
                    let similar = find_similar(key, available_keys);
                    return Err(FnoxError::SecretNotFound {
                        key: key.clone(),
                        profile: Config::display_profiles(&profile),
                        config_path: config.secret_sources.get(key).cloned(),
                        suggestion: format_suggestions(&similar),
                    });
                }
            }
            // A provider may read credentials from other fnox secrets (e.g.
            // `OP_SERVICE_ACCOUNT_TOKEN`). Resolve those first so they reach the
            // environment, without resolving anything else.
            let providers = config.get_providers(&profile)?;
            let default_provider = config.get_default_provider(&profile).ok().flatten();
            let mut credential_roots: Vec<String> = Vec::new();
            for key in &self.key {
                let secret = &profile_secrets[key];
                if secret.value().is_none() {
                    continue;
                }
                let name = secret.provider().or(default_provider.as_deref());
                if let Some(provider) = name.and_then(|name| providers.get(name)) {
                    for dep in provider.env_dependencies() {
                        if profile_secrets.contains_key(*dep) {
                            credential_roots.push(dep.to_string());
                        }
                    }
                }
            }
            if !credential_roots.is_empty() {
                let credentials = crate::secret_resolver::dependency_closure(
                    &config,
                    &profile,
                    &profile_secrets,
                    &credential_roots,
                )?;
                crate::daemon::resolve_batch(
                    cli,
                    &config,
                    &profile,
                    &credentials,
                    crate::daemon::Purpose::Export,
                    true,
                )
                .await?;
            }
            profile_secrets = self
                .key
                .iter()
                .map(|key| (key.clone(), profile_secrets[key].clone()))
                .collect();
        } else if !self.all {
            profile_secrets.retain(|_, sc| sc.env_mode().in_shell());
        }

        // Named keys are resolved one at a time like `fnox get`, which pulls in
        // only the secrets each value interpolates. Batch resolution would also
        // resolve fallback-only dependencies that a working secret never uses.
        let resolved_secrets = if self.key.is_empty() {
            crate::daemon::resolve_batch(
                cli,
                &config,
                &profile,
                &profile_secrets,
                crate::daemon::Purpose::Export,
                true,
            )
            .await?
        } else {
            let mut resolved = IndexMap::new();
            for (key, secret_config) in &profile_secrets {
                let value = crate::daemon::resolve_one(
                    cli,
                    &config,
                    &profile,
                    key,
                    secret_config,
                    crate::daemon::Purpose::Export,
                )
                .await?;
                resolved.insert(key.clone(), value);
            }
            resolved
        };

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
            profile: Config::display_profiles(&profile),
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

        if self.header {
            append_metadata_header(&mut output, data.metadata.as_ref());
        }

        for (key, value) in &data.secrets {
            output.push_str(&format!("{}={}\n", key, dotenv_quote(value)));
        }

        Ok(output)
    }

    fn export_as_shell(&self, data: &ExportData) -> Result<String> {
        let mut output = String::new();

        if self.header {
            append_metadata_header(&mut output, data.metadata.as_ref());
        }

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

    // Docker Compose interpolates `$` in unquoted and double-quoted dotenv
    // values. Single quotes keep secret values literal.
    if value.contains('$') && is_single_quote_safe(value) {
        return format!("'{}'", value.replace('\'', "\\'"));
    }

    // Use `--format shell` for sourceable shell output.
    dotenv_double_quote(value, value.contains('$'))
}

fn is_single_quote_safe(value: &str) -> bool {
    let mut backslashes = 0;
    for c in value.chars() {
        match c {
            '\\' => backslashes += 1,
            '\'' if backslashes % 2 == 1 => return false,
            _ => backslashes = 0,
        }
    }
    backslashes % 2 == 0
}

fn dotenv_double_quote(value: &str, escape_dollars: bool) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '$' if escape_dollars => quoted.push_str("\\$"),
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
        assert_eq!(dotenv_quote("a\nb\tc`d"), "\"a\\nb\\tc`d\"");
    }

    #[test]
    fn dotenv_quote_single_quotes_dollar_values() {
        assert_eq!(dotenv_quote("secret$value"), "'secret$value'");
        assert_eq!(dotenv_quote("${TOKEN:-fallback}"), "'${TOKEN:-fallback}'");
        assert_eq!(dotenv_quote("$$test"), "'$$test'");
        assert_eq!(dotenv_quote("it's $5"), "'it\\'s $5'");
        assert_eq!(dotenv_quote("a\n$b"), "'a\n$b'");
        assert_eq!(dotenv_quote("secret$value\\"), "\"secret\\$value\\\\\"");
        assert_eq!(dotenv_quote("a\\'b $5"), "\"a\\\\'b \\$5\"");
        assert_eq!(
            dotenv_quote("prefix\\'$value\ncontinuation"),
            "\"prefix\\\\'\\$value\\ncontinuation\""
        );
    }
}
