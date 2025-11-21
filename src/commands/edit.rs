use crate::commands::Cli;
use crate::config::{Config, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::providers::{ProviderCapability, get_provider};
use crate::secret_resolver;
use clap::Args;
use indexmap::IndexMap;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, Table, Value};

#[derive(Debug, Args)]
pub struct EditCommand {}

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
        let toml_content = fs::read_to_string(&cli.config)
            .map_err(|e| FnoxError::Config(format!("Failed to read config file: {}", e)))?;
        let mut doc = toml_content
            .parse::<DocumentMut>()
            .map_err(|e| FnoxError::Config(format!("Failed to parse TOML: {}", e)))?;

        // Step 2: Collect all secrets from all profiles
        let mut all_secrets = Vec::new();

        // Collect secrets from top-level [secrets] section
        if !config.secrets.is_empty() {
            self.collect_secrets(
                &config,
                "default",
                &config.secrets,
                &mut all_secrets,
                cli.age_key_file.as_ref().map(PathBuf::from).as_deref(),
            )
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
                    cli.age_key_file.as_ref().map(PathBuf::from).as_deref(),
                )
                .await?;
            }
        }

        // Step 3: Decrypt/fetch all secrets (force error mode in edit)
        tracing::debug!("Decrypting {} secrets", all_secrets.len());
        for secret_entry in &mut all_secrets {
            // In edit mode, override if_missing to "error" to get the actual error
            let mut edit_secret_config = secret_entry.original_config.clone();
            edit_secret_config.if_missing = Some(crate::config::IfMissing::Error);

            secret_entry.plaintext_value = secret_resolver::resolve_secret(
                &config,
                &profile,
                &secret_entry.key,
                &edit_secret_config,
                cli.age_key_file.as_ref().map(PathBuf::from).as_deref(),
            )
            .await?;
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
        let modified_doc = modified_content
            .parse::<DocumentMut>()
            .map_err(|e| FnoxError::Config(format!("Invalid TOML after edit: {}", e)))?;

        // Step 7: Detect changes and re-encrypt/update
        tracing::debug!("Processing changes and re-encrypting secrets");
        self.process_changes(
            &config,
            &mut doc,
            &modified_doc,
            &all_secrets,
            &profile,
            cli.age_key_file.as_ref().map(PathBuf::from).as_deref(),
        )
        .await?;

        // Step 8: Save updated config
        fs::write(&cli.config, doc.to_string())
            .map_err(|e| FnoxError::Config(format!("Failed to write config file: {}", e)))?;

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
        _age_key_file: Option<&Path>,
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
                    let provider = get_provider(provider_config)?;
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
        let header = format!(
            "# FNOX EDIT - Decrypted Secrets\n\
             # This is a temporary file with decrypted secret values.\n\
             # Secrets marked as READ-ONLY cannot be modified (from 1Password, Bitwarden, etc.)\n\
             # After you save and close this file, fnox will re-encrypt changed secrets.\n\
             # DO NOT share this file as it contains plaintext secrets!\n\n{}",
            decrypted_doc
        );

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

    /// Process changes between original and modified TOML, re-encrypting as needed
    async fn process_changes(
        &self,
        config: &Config,
        original_doc: &mut DocumentMut,
        modified_doc: &DocumentMut,
        all_secrets: &[SecretEntry],
        profile: &str,
        age_key_file: Option<&Path>,
    ) -> Result<()> {
        // Create a map of secrets by (profile, key) to avoid collisions
        let secrets_map: HashMap<_, _> = all_secrets
            .iter()
            .map(|s| ((s.profile.clone(), s.key.clone()), s))
            .collect();

        // Process [secrets] section
        if let Some(modified_secrets) = modified_doc.get("secrets").and_then(|item| item.as_table())
            && let Some(original_secrets) = original_doc
                .get_mut("secrets")
                .and_then(|item| item.as_table_mut())
        {
            self.process_secrets_table_changes(
                config,
                original_secrets,
                modified_secrets,
                "default",
                &secrets_map,
                profile,
                age_key_file,
            )
            .await?;
        }

        // Process [profiles.*] sections
        if let Some(modified_profiles) = modified_doc
            .get("profiles")
            .and_then(|item| item.as_table())
        {
            // Ensure original_profiles exists
            if original_doc.get("profiles").is_none() {
                original_doc.insert("profiles", toml_edit::Item::Table(toml_edit::Table::new()));
            }

            let original_profiles = original_doc
                .get_mut("profiles")
                .and_then(|item| item.as_table_mut())
                .expect("profiles should be a table");

            for (profile_name, modified_profile_item) in modified_profiles.iter() {
                let profile_name_str = profile_name.to_string();

                if let Some(modified_profile_table) = modified_profile_item.as_table() {
                    // If the profile doesn't exist in original, create it
                    if original_profiles.get(profile_name).is_none() {
                        tracing::debug!("Creating new profile section: {}", profile_name_str);
                        // Copy the entire profile structure from modified
                        original_profiles.insert(profile_name, modified_profile_item.clone());
                    }

                    // Process secrets if they exist
                    if let Some(modified_secrets) = modified_profile_table
                        .get("secrets")
                        .and_then(|item| item.as_table())
                    {
                        // Now process the secrets
                        if let Some(original_profile_item) = original_profiles.get_mut(profile_name)
                            && let Some(original_profile_table) =
                                original_profile_item.as_table_mut()
                        {
                            // Ensure secrets table exists in the profile
                            if original_profile_table.get("secrets").is_none() {
                                original_profile_table.insert(
                                    "secrets",
                                    toml_edit::Item::Table(toml_edit::Table::new()),
                                );
                            }

                            if let Some(original_secrets) = original_profile_table
                                .get_mut("secrets")
                                .and_then(|item| item.as_table_mut())
                            {
                                self.process_secrets_table_changes(
                                    config,
                                    original_secrets,
                                    modified_secrets,
                                    &profile_name_str,
                                    &secrets_map,
                                    profile,
                                    age_key_file,
                                )
                                .await?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process changes in a specific secrets table
    #[allow(clippy::too_many_arguments)]
    async fn process_secrets_table_changes(
        &self,
        config: &Config,
        original_secrets: &mut Table,
        modified_secrets: &Table,
        secret_profile: &str,
        secrets_map: &HashMap<(String, String), &SecretEntry>,
        profile: &str,
        age_key_file: Option<&Path>,
    ) -> Result<()> {
        for (key, modified_value) in modified_secrets.iter() {
            let key_str = key.to_string();

            // Get the secret entry metadata using (profile, key) composite key
            let lookup_key = (secret_profile.to_string(), key_str.clone());

            // Handle new secrets
            if secrets_map.get(&lookup_key).is_none() {
                // New secret added - encrypt and add to config
                tracing::debug!("New secret '{}' detected, adding to config", key_str);

                // Extract plaintext value and provider from modified value
                let (plaintext, provider_name) =
                    if let Some(inline_table) = modified_value.as_inline_table() {
                        let plaintext = inline_table.get("value").and_then(|v| v.as_str());
                        let provider = inline_table.get("provider").and_then(|v| v.as_str());
                        (plaintext, provider)
                    } else if let Some(table) = modified_value.as_table() {
                        let plaintext = table.get("value").and_then(|v| v.as_str());
                        let provider = table.get("provider").and_then(|v| v.as_str());
                        (plaintext, provider)
                    } else {
                        continue;
                    };

                let Some(plaintext) = plaintext else {
                    continue;
                };

                // Determine provider to use (explicit or default)
                let provider_name = if let Some(prov) = provider_name {
                    prov.to_string()
                } else if let Some(default_prov) = config.get_default_provider(profile)? {
                    default_prov
                } else {
                    // No provider specified and no default - store as plaintext
                    tracing::warn!(
                        "No provider specified for new secret '{}', storing as plaintext",
                        key_str
                    );
                    original_secrets.insert(&key_str, modified_value.clone());
                    continue;
                };

                // Get provider config and encrypt
                let providers = config.get_providers(profile);
                let Some(provider_config) = providers.get(&provider_name) else {
                    return Err(FnoxError::Config(format!(
                        "Provider '{}' not found for new secret '{}'",
                        provider_name, key_str
                    )));
                };

                let provider = get_provider(provider_config)?;

                // Use the unified put_secret method that handles both encryption and remote storage
                let encrypted_value = provider
                    .put_secret(&key_str, plaintext, age_key_file)
                    .await?;

                // Add to original document with encrypted value
                let mut new_value = modified_value.clone();
                if let Some(inline_table) = new_value.as_inline_table_mut() {
                    inline_table.insert("value", Value::from(encrypted_value.as_str()));
                } else if let Some(table) = new_value.as_table_mut() {
                    table.insert("value", toml_edit::value(encrypted_value.as_str()));
                }
                original_secrets.insert(&key_str, new_value);
                continue;
            }

            let secret_entry = secrets_map.get(&lookup_key).unwrap();

            // Get modified plaintext value (support both inline table and table formats)
            let modified_plaintext = if let Some(inline_table) = modified_value.as_inline_table() {
                inline_table.get("value").and_then(|v| v.as_str())
            } else if let Some(table) = modified_value.as_table() {
                table.get("value").and_then(|v| v.as_str())
            } else {
                None
            };

            let Some(modified_plaintext) = modified_plaintext else {
                continue;
            };

            // Check if this is a read-only secret
            if secret_entry.is_read_only {
                // Check if it changed
                if Some(modified_plaintext) != secret_entry.plaintext_value.as_deref() {
                    return Err(FnoxError::Config(format!(
                        "Cannot modify read-only secret '{}' from provider '{}'",
                        key_str,
                        secret_entry
                            .provider_name
                            .as_ref()
                            .unwrap_or(&"unknown".to_string())
                    )));
                }
                // No change, skip this secret
                continue;
            }

            // Check if the value changed
            if Some(modified_plaintext) == secret_entry.plaintext_value.as_deref() {
                // No change, skip
                continue;
            }

            tracing::debug!("Secret '{}' changed, re-encrypting", key_str);

            // Re-encrypt the new value using the unified put_secret method
            let new_encrypted_value = if let Some(ref provider_name) = secret_entry.provider_name {
                let providers = config.get_providers(profile);
                if let Some(provider_config) = providers.get(provider_name) {
                    let provider = get_provider(provider_config)?;
                    // Use the unified put_secret method that handles both encryption and remote storage
                    provider
                        .put_secret(&key_str, modified_plaintext, age_key_file)
                        .await?
                } else {
                    // Provider not found, store plaintext
                    modified_plaintext.to_string()
                }
            } else {
                // No provider, store plaintext
                modified_plaintext.to_string()
            };

            // Update the original document with the new encrypted value
            if let Some(original_value) = original_secrets.get_mut(&key_str) {
                if let Some(original_inline_table) = original_value.as_inline_table_mut() {
                    original_inline_table
                        .insert("value", Value::from(new_encrypted_value.as_str()));
                } else if let Some(original_table) = original_value.as_table_mut() {
                    original_table.insert("value", toml_edit::value(new_encrypted_value.as_str()));
                }
            }
        }

        // Check for deleted secrets
        let modified_keys: std::collections::HashSet<_> = modified_secrets
            .iter()
            .map(|(k, _)| k.to_string())
            .collect();

        let original_keys: Vec<_> = original_secrets
            .iter()
            .map(|(k, _)| k.to_string())
            .collect();

        for key in original_keys {
            if !modified_keys.contains(key.as_str()) {
                tracing::debug!("Secret '{}' deleted", key);
                original_secrets.remove(&key);
            }
        }

        Ok(())
    }
}
