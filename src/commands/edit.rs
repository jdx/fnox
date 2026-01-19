use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::process::Command;

use clap::Args;
use indexmap::IndexMap;
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, Table, Value};

use crate::commands::Cli;
use crate::config::{Config, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::providers::{ProviderCapability, get_provider_resolved};
use crate::secret_resolver;

/// Header added to temporary edit file for user reference
const TEMP_FILE_HEADER: &str = "\
# FNOX EDIT - Decrypted Secrets
# This is a temporary file with decrypted secret values.
# Secrets marked as READ-ONLY cannot be modified (from 1Password, Bitwarden, etc.)
# After you save and close this file, fnox will re-encrypt changed secrets.
# DO NOT share this file as it contains plaintext secrets!

";

#[derive(Debug, Args)]
pub struct EditCommand;

/// Represents a secret with its metadata for tracking during editing
#[derive(Debug, Clone)]
struct SecretEntry {
    /// The profile this secret belongs to ("default" for top-level secrets)
    profile: String,
    /// The secret key (environment variable name)
    key: String,
    /// The original secret config from the config file
    original_config: SecretConfig,
    /// The decrypted/fetched plaintext value (if available)
    plaintext_value: Option<String>,
    /// Whether this secret is from a read-only provider (can't be modified)
    is_read_only: bool,
    /// The provider name used for this secret
    provider_name: Option<String>,
}

impl EditCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());
        tracing::debug!("Starting enhanced edit with profile: {}", profile);

        // Step 1: Load raw TOML with toml_edit to preserve formatting
        let toml_content =
            fs::read_to_string(&cli.config).map_err(|source| FnoxError::ConfigReadFailed {
                path: cli.config.clone(),
                source,
            })?;
        let doc = toml_content
            .parse::<DocumentMut>()
            .map_err(|e| FnoxError::Config(format!("Failed to parse TOML: {}", e)))?;

        // Step 2: Collect all secrets from all profiles
        let mut all_secrets = Vec::new();

        // Collect secrets from top-level [secrets] section
        if !config.secrets.is_empty() {
            self.collect_secrets(&config, "default", &config.secrets, &mut all_secrets)
                .await?;
        }

        // Collect secrets from all [profiles.*] sections
        for (profile_name, profile_config) in &config.profiles {
            if !profile_config.secrets.is_empty() {
                self.collect_secrets(
                    &config,
                    profile_name,
                    &profile_config.secrets,
                    &mut all_secrets,
                )
                .await?;
            }
        }

        // Step 3: Decrypt/fetch all secrets (force error mode in edit)
        tracing::debug!("Decrypting {} secrets", all_secrets.len());
        let mut secrets_by_profile: IndexMap<String, IndexMap<String, SecretConfig>> =
            IndexMap::new();
        for secret_entry in &all_secrets {
            // In edit mode, override if_missing to "error" to get the actual error
            let mut edit_secret_config = secret_entry.original_config.clone();
            edit_secret_config.if_missing = Some(crate::config::IfMissing::Error);
            secrets_by_profile
                .entry(secret_entry.profile.clone())
                .or_default()
                .insert(secret_entry.key.clone(), edit_secret_config);
        }

        let mut resolved_by_profile: IndexMap<String, IndexMap<String, Option<String>>> =
            IndexMap::new();
        for (profile_name, secrets) in secrets_by_profile {
            let resolved =
                secret_resolver::resolve_secrets_batch(&config, &profile_name, &secrets).await?;
            resolved_by_profile.insert(profile_name, resolved);
        }

        for secret_entry in &mut all_secrets {
            secret_entry.plaintext_value = resolved_by_profile
                .get(&secret_entry.profile)
                .and_then(|resolved| resolved.get(&secret_entry.key))
                .cloned()
                .flatten();
        }

        // Step 4: Create temporary file with decrypted TOML
        let temp_file = self.create_decrypted_temp_file(&doc, &all_secrets)?;
        let temp_path = temp_file.path().to_path_buf();

        // Step 5: Open editor on temp file
        tracing::debug!("Opening editor on temporary file");
        let editor = env::var("EDITOR")
            .or_else(|_| env::var("VISUAL"))
            .unwrap_or_else(|_| {
                if cfg!(target_os = "windows") {
                    "notepad".to_string()
                } else {
                    "vi".to_string()
                }
            });

        let status = Command::new(&editor)
            .arg(&temp_path)
            .status()
            .map_err(|e| FnoxError::EditorLaunchFailed {
                editor: editor.clone(),
                source: e,
            })?;

        if !status.success()
            && let Some(code) = status.code()
        {
            return Err(FnoxError::EditorExitFailed {
                editor: editor.clone(),
                status: code,
            });
        }

        // Step 6: Read and parse modified temp file
        tracing::debug!("Reading modified temporary file");
        let modified_content = fs::read_to_string(&temp_path)
            .map_err(|e| FnoxError::Config(format!("Failed to read temporary file: {}", e)))?;
        let mut modified_doc = modified_content
            .parse::<DocumentMut>()
            .map_err(|e| FnoxError::Config(format!("Invalid TOML after edit: {}", e)))?;

        // Step 7: Re-encrypt secrets in the modified document
        // This preserves all user edits (comments, formatting, non-secret config)
        tracing::debug!("Re-encrypting secrets in modified document");

        // Parse a fresh config from the modified content to recognize new providers
        // Strip the temp header first as it's not valid TOML
        let modified_toml = Self::strip_temp_header(&modified_content);
        let modified_config: Config = toml_edit::de::from_str(&modified_toml)
            .map_err(|e| FnoxError::Config(format!("Invalid configuration after edit: {}", e)))?;

        self.reencrypt_secrets(&modified_config, &mut modified_doc, &all_secrets)
            .await?;

        // Step 8: Save the modified config (preserves all user edits)
        // Strip the temporary file header comments before saving
        let output = Self::strip_temp_header(&modified_doc.to_string());
        fs::write(&cli.config, output).map_err(|source| FnoxError::ConfigWriteFailed {
            path: cli.config.clone(),
            source,
        })?;

        let check = console::style("✓").green();
        let styled_config = console::style(cli.config.display()).cyan();
        println!("{check} Configuration file {styled_config} updated with re-encrypted secrets");

        Ok(())
    }

    /// Collect secrets from a specific secrets table (top-level or profile)
    async fn collect_secrets(
        &self,
        config: &Config,
        profile: &str,
        secrets: &IndexMap<String, SecretConfig>,
        all_secrets: &mut Vec<SecretEntry>,
    ) -> Result<()> {
        for (key, secret_config) in secrets {
            // Determine provider and check if read-only
            let provider_name = if let Some(ref prov) = secret_config.provider {
                Some(prov.clone())
            } else {
                config.get_default_provider(profile)?
            };

            let (is_read_only, resolved_provider_name) = if let Some(ref prov_name) = provider_name
            {
                let providers = config.get_providers(profile);
                if let Some(provider_config) = providers.get(prov_name) {
                    let provider =
                        get_provider_resolved(config, profile, prov_name, provider_config).await?;
                    let capabilities = provider.capabilities();
                    let is_read_only = capabilities.contains(&ProviderCapability::RemoteRead)
                        && !capabilities.contains(&ProviderCapability::Encryption)
                        && !capabilities.contains(&ProviderCapability::RemoteStorage);
                    (is_read_only, Some(prov_name.clone()))
                } else {
                    (false, provider_name)
                }
            } else {
                (false, None)
            };

            all_secrets.push(SecretEntry {
                profile: profile.to_string(),
                key: key.clone(),
                original_config: secret_config.clone(),
                plaintext_value: None,
                is_read_only,
                provider_name: resolved_provider_name,
            });
        }
        Ok(())
    }

    /// Create a temporary file with decrypted secrets
    fn create_decrypted_temp_file(
        &self,
        doc: &DocumentMut,
        all_secrets: &[SecretEntry],
    ) -> Result<NamedTempFile> {
        let mut temp_file = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .map_err(|e| FnoxError::Config(format!("Failed to create temporary file: {}", e)))?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = temp_file
                .as_file()
                .metadata()
                .map_err(|e| FnoxError::Config(format!("Failed to get file metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            temp_file
                .as_file()
                .set_permissions(perms)
                .map_err(|e| FnoxError::Config(format!("Failed to set file permissions: {}", e)))?;
        }

        // Clone the document and replace encrypted values with plaintext
        let mut decrypted_doc = doc.clone();

        // Create a map of secrets by (profile, key) for quick lookup to avoid collisions
        let secrets_map: HashMap<_, _> = all_secrets
            .iter()
            .map(|s| ((s.profile.clone(), s.key.clone()), s))
            .collect();

        // Replace values in [secrets] section
        if let Some(secrets_table) = decrypted_doc
            .get_mut("secrets")
            .and_then(|item| item.as_table_mut())
        {
            self.replace_secrets_in_table(secrets_table, "default", &secrets_map)?;
        }

        // Replace values in [profiles.*] sections
        if let Some(profiles_table) = decrypted_doc
            .get_mut("profiles")
            .and_then(|item| item.as_table_mut())
        {
            for (profile_name, profile_item) in profiles_table.iter_mut() {
                let profile_name_str = profile_name.to_string();
                if let Some(profile_table) = profile_item.as_table_mut()
                    && let Some(secrets_table) = profile_table
                        .get_mut("secrets")
                        .and_then(|item| item.as_table_mut())
                {
                    self.replace_secrets_in_table(secrets_table, &profile_name_str, &secrets_map)?;
                }
            }
        }

        // Add header comment
        let header = format!("{}{}", TEMP_FILE_HEADER, decrypted_doc);

        temp_file
            .write_all(header.as_bytes())
            .map_err(|e| FnoxError::Config(format!("Failed to write to temporary file: {}", e)))?;

        temp_file
            .flush()
            .map_err(|e| FnoxError::Config(format!("Failed to flush temporary file: {}", e)))?;

        Ok(temp_file)
    }

    /// Replace encrypted secret values with plaintext in a TOML table
    fn replace_secrets_in_table(
        &self,
        secrets_table: &mut Table,
        profile: &str,
        secrets_map: &HashMap<(String, String), &SecretEntry>,
    ) -> Result<()> {
        for (key, value) in secrets_table.iter_mut() {
            let key_string = key.to_string();
            let lookup_key = (profile.to_string(), key_string.clone());
            if let Some(secret_entry) = secrets_map.get(&lookup_key) {
                // Try inline table first (KEY = { provider = "...", value = "..." })
                if let Some(inline_table) = value.as_inline_table_mut() {
                    if let Some(plaintext) = &secret_entry.plaintext_value {
                        inline_table.insert("value", Value::from(plaintext.as_str()));
                    }
                } else if let Some(table) = value.as_table_mut() {
                    // Handle regular table format ([secrets.KEY])
                    if let Some(plaintext) = &secret_entry.plaintext_value {
                        table.insert("value", toml_edit::value(plaintext.as_str()));
                    }
                }

                // Note: We can't easily add inline comments to tables in toml_edit
                // The read-only status will be enforced when processing changes
            }
        }
        Ok(())
    }

    /// Re-encrypt secrets in the modified document
    /// This preserves all user edits (comments, formatting, non-secret config)
    async fn reencrypt_secrets(
        &self,
        config: &Config,
        modified_doc: &mut DocumentMut,
        all_secrets: &[SecretEntry],
    ) -> Result<()> {
        // Create a map of secrets by (profile, key) to avoid collisions
        let secrets_map: HashMap<_, _> = all_secrets
            .iter()
            .map(|s| ((s.profile.clone(), s.key.clone()), s))
            .collect();

        // Process [secrets] section
        if let Some(secrets_table) = modified_doc
            .get_mut("secrets")
            .and_then(|item| item.as_table_mut())
        {
            self.reencrypt_secrets_table(config, secrets_table, "default", &secrets_map)
                .await?;
        }

        // Process [profiles.*] sections
        if let Some(profiles_table) = modified_doc
            .get_mut("profiles")
            .and_then(|item| item.as_table_mut())
        {
            // Collect profile names first to avoid borrow issues
            let profile_names: Vec<_> = profiles_table.iter().map(|(k, _)| k.to_string()).collect();

            for profile_name in profile_names {
                if let Some(profile_item) = profiles_table.get_mut(&profile_name)
                    && let Some(profile_table) = profile_item.as_table_mut()
                    && let Some(secrets_table) = profile_table
                        .get_mut("secrets")
                        .and_then(|item| item.as_table_mut())
                {
                    self.reencrypt_secrets_table(
                        config,
                        secrets_table,
                        &profile_name,
                        &secrets_map,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    /// Re-encrypt secrets in a specific secrets table
    async fn reencrypt_secrets_table(
        &self,
        config: &Config,
        secrets_table: &mut Table,
        secret_profile: &str,
        secrets_map: &HashMap<(String, String), &SecretEntry>,
    ) -> Result<()> {
        // Collect keys first to avoid borrow issues when mutating
        let keys: Vec<_> = secrets_table.iter().map(|(k, _)| k.to_string()).collect();

        for key_str in keys {
            let lookup_key = (secret_profile.to_string(), key_str.clone());

            // Get the current value from the table
            let Some(value) = secrets_table.get_mut(&key_str) else {
                continue;
            };

            // Extract plaintext value and provider from the value
            let (plaintext, explicit_provider) = if let Some(inline_table) = value.as_inline_table()
            {
                let plaintext = inline_table.get("value").and_then(|v| v.as_str());
                let provider = inline_table.get("provider").and_then(|v| v.as_str());
                (plaintext, provider.map(String::from))
            } else if let Some(table) = value.as_table() {
                let plaintext = table.get("value").and_then(|v| v.as_str());
                let provider = table.get("provider").and_then(|v| v.as_str());
                (plaintext, provider.map(String::from))
            } else {
                continue;
            };

            let Some(plaintext) = plaintext else {
                continue;
            };

            // Check if this is an existing secret or a new one
            if let Some(secret_entry) = secrets_map.get(&lookup_key) {
                // Existing secret - check if read-only
                if secret_entry.is_read_only {
                    // Verify it wasn't changed
                    if Some(plaintext) != secret_entry.plaintext_value.as_deref() {
                        return Err(FnoxError::Config(format!(
                            "Cannot modify read-only secret '{}' from provider '{}'",
                            key_str,
                            secret_entry
                                .provider_name
                                .as_ref()
                                .unwrap_or(&"unknown".to_string())
                        )));
                    }
                    // Read-only and unchanged - restore original encrypted value
                    if let Some(original_value) = &secret_entry.original_config.value {
                        Self::set_secret_value(value, original_value);
                    }
                    continue;
                }

                // Check if the value or provider changed
                // Compare explicit provider fields (not resolved provider names)
                // to avoid false positives when secrets use default provider
                let value_changed = Some(plaintext) != secret_entry.plaintext_value.as_deref();
                let provider_changed =
                    explicit_provider.as_ref() != secret_entry.original_config.provider.as_ref();

                if !value_changed && !provider_changed {
                    // Nothing changed - restore original encrypted value to avoid version control churn
                    if let Some(original_value) = &secret_entry.original_config.value {
                        Self::set_secret_value(value, original_value);
                    }
                    continue;
                }

                // Value or provider changed - re-encrypt
                // If explicit provider is set, use it; otherwise use default provider for this secret's profile
                tracing::debug!("Secret '{}' changed, re-encrypting", key_str);
                let provider_to_use = if let Some(ref prov) = explicit_provider {
                    Some(prov.clone())
                } else {
                    config.get_default_provider(secret_profile)?
                };
                let encrypted_value = if let Some(provider_name) = provider_to_use {
                    let providers = config.get_providers(secret_profile);
                    if let Some(provider_config) = providers.get(&provider_name) {
                        let provider = get_provider_resolved(
                            config,
                            secret_profile,
                            &provider_name,
                            provider_config,
                        )
                        .await?;
                        provider.put_secret(&key_str, plaintext).await?
                    } else {
                        plaintext.to_string()
                    }
                } else {
                    plaintext.to_string()
                };

                Self::set_secret_value(value, &encrypted_value);
            } else {
                // New secret added by user
                tracing::debug!("New secret '{}' detected, encrypting", key_str);

                // Determine provider to use (from this secret's profile)
                let provider_name = if let Some(prov) = explicit_provider {
                    prov
                } else if let Some(default_prov) = config.get_default_provider(secret_profile)? {
                    default_prov
                } else {
                    // No provider - keep as plaintext
                    tracing::warn!(
                        "No provider specified for new secret '{}', storing as plaintext",
                        key_str
                    );
                    continue;
                };

                // Encrypt with the provider from this secret's profile
                let providers = config.get_providers(secret_profile);
                let Some(provider_config) = providers.get(&provider_name) else {
                    return Err(FnoxError::Config(format!(
                        "Provider '{}' not found for new secret '{}'",
                        provider_name, key_str
                    )));
                };

                let provider =
                    get_provider_resolved(config, secret_profile, &provider_name, provider_config)
                        .await?;
                let encrypted_value = provider.put_secret(&key_str, plaintext).await?;

                Self::set_secret_value(value, &encrypted_value);
            }
        }

        Ok(())
    }

    /// Helper to set the value field in a secret (handles both inline table and table formats)
    fn set_secret_value(item: &mut toml_edit::Item, value: &str) {
        if let Some(inline_table) = item.as_inline_table_mut() {
            inline_table.insert("value", Value::from(value));
        } else if let Some(table) = item.as_table_mut() {
            table.insert("value", toml_edit::value(value));
        }
    }

    /// Strip the temporary file header that was added for user reference
    fn strip_temp_header(content: &str) -> String {
        // Only strip if the content starts with our exact header
        // This avoids accidentally removing user comments that happen to match patterns
        content
            .strip_prefix(TEMP_FILE_HEADER)
            .unwrap_or(content)
            .to_string()
    }
}
