use crate::commands::Cli;
use crate::config::{Config, ProviderConfig, SecretConfig};
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

        // Step 3: Decrypt/fetch all secrets (fail immediately on error per user preference)
        tracing::debug!("Decrypting {} secrets", all_secrets.len());
        for secret_entry in &mut all_secrets {
            secret_entry.plaintext_value = secret_resolver::resolve_secret(
                &config,
                &profile,
                &secret_entry.key,
                &secret_entry.original_config,
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
        let mut temp_file = NamedTempFile::new()
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
            let lookup_key = (profile.to_string(), key_string);
            if let Some(secret_entry) = secrets_map.get(&lookup_key) {
                // Get the inline table for this secret
                if let Some(inline_table) = value.as_inline_table_mut() {
                    // Replace the 'value' field with plaintext
                    if let Some(plaintext) = &secret_entry.plaintext_value {
                        inline_table.insert("value", Value::from(plaintext.as_str()));
                    }

                    // Note: We can't easily add inline comments to inline tables in toml_edit
                    // The read-only status will be enforced when processing changes
                }
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
            && let Some(original_profiles) = original_doc
                .get_mut("profiles")
                .and_then(|item| item.as_table_mut())
        {
            for (profile_name, modified_profile_item) in modified_profiles.iter() {
                let profile_name_str = profile_name.to_string();
                if let Some(modified_profile_table) = modified_profile_item.as_table()
                    && let Some(modified_secrets) = modified_profile_table
                        .get("secrets")
                        .and_then(|item| item.as_table())
                    && let Some(original_profile_item) = original_profiles.get_mut(profile_name)
                    && let Some(original_profile_table) = original_profile_item.as_table_mut()
                    && let Some(original_secrets) = original_profile_table
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
            let Some(secret_entry) = secrets_map.get(&lookup_key) else {
                // New secret added - not supported in edit mode
                return Err(FnoxError::Config(format!(
                    "New secret '{}' detected. Use 'fnox set' to add new secrets.",
                    key_str
                )));
            };

            // Check if this is a read-only secret
            if secret_entry.is_read_only {
                // Get modified plaintext value
                let modified_plaintext = modified_value
                    .as_inline_table()
                    .and_then(|t| t.get("value"))
                    .and_then(|v| v.as_str());

                // Check if it changed
                if modified_plaintext != secret_entry.plaintext_value.as_deref() {
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

            // Get the modified plaintext value
            let Some(modified_inline_table) = modified_value.as_inline_table() else {
                continue;
            };

            let Some(modified_plaintext) =
                modified_inline_table.get("value").and_then(|v| v.as_str())
            else {
                continue;
            };

            // Check if the value changed
            if Some(modified_plaintext) == secret_entry.plaintext_value.as_deref() {
                // No change, skip
                continue;
            }

            tracing::debug!("Secret '{}' changed, re-encrypting", key_str);

            // Re-encrypt the new value
            let new_encrypted_value = if let Some(ref provider_name) = secret_entry.provider_name {
                let providers = config.get_providers(profile);
                if let Some(provider_config) = providers.get(provider_name) {
                    let provider = get_provider(provider_config)?;
                    let capabilities = provider.capabilities();

                    if capabilities.contains(&ProviderCapability::Encryption) {
                        // Encryption provider - encrypt the value
                        provider.encrypt(modified_plaintext, age_key_file).await?
                    } else if capabilities.contains(&ProviderCapability::RemoteStorage) {
                        // Remote storage provider - push to remote and store only the key name
                        tracing::debug!(
                            "Updating secret '{}' in remote provider '{}'",
                            key_str,
                            provider_name
                        );

                        match provider_config {
                            ProviderConfig::AwsSecretsManager { region, prefix } => {
                                let sm_provider =
                                    crate::providers::aws_sm::AwsSecretsManagerProvider::new(
                                        region.clone(),
                                        prefix.clone(),
                                    );
                                let secret_name = sm_provider.get_secret_name(&key_str);
                                sm_provider
                                    .put_secret(&secret_name, modified_plaintext)
                                    .await?;

                                // Store just the key name (without prefix) in config
                                key_str.clone()
                            }
                            ProviderConfig::Keychain { service, prefix } => {
                                let keychain_provider =
                                    crate::providers::keychain::KeychainProvider::new(
                                        service.clone(),
                                        prefix.clone(),
                                    );
                                keychain_provider
                                    .put_secret(&key_str, modified_plaintext)
                                    .await?;

                                // Store just the key name (without prefix) in config
                                key_str.clone()
                            }
                            _ => {
                                // Other remote storage providers not yet implemented
                                return Err(FnoxError::Config(format!(
                                    "Remote storage update not yet implemented for provider '{}'. \
                                    Please use 'fnox set' to update this secret.",
                                    provider_name
                                )));
                            }
                        }
                    } else {
                        // RemoteRead or unknown - shouldn't get here due to read-only check
                        modified_plaintext.to_string()
                    }
                } else {
                    // Provider not found, store plaintext
                    modified_plaintext.to_string()
                }
            } else {
                // No provider, store plaintext
                modified_plaintext.to_string()
            };

            // Update the original document with the new encrypted value
            if let Some(original_value) = original_secrets.get_mut(&key_str)
                && let Some(original_inline_table) = original_value.as_inline_table_mut()
            {
                original_inline_table.insert("value", Value::from(new_encrypted_value.as_str()));
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
