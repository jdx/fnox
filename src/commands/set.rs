use crate::commands::Cli;
use crate::config::{self, Config, IfMissing};
use crate::error::{FnoxError, Result};
use crate::generate::{self, GenerateKind};
use crate::providers::ProviderCapability;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Resolve a remote key without carrying a reference across providers.
fn resolve_remote_key_name<'a>(
    key: &'a str,
    key_name: Option<&'a str>,
    existing_secret: Option<&'a config::SecretConfig>,
    provider_name: &str,
) -> &'a str {
    key_name
        .or_else(|| {
            existing_secret
                .filter(|secret| secret.provider() == Some(provider_name))
                .and_then(config::SecretConfig::value)
        })
        .unwrap_or(key)
}

/// What `SetCommand::store_at` wrote
pub(crate) struct Stored {
    pub write_profile: String,
    pub secret: config::SecretConfig,
    pub generated: Option<String>,
}

/// The project config file `fnox set` writes to without `--global`.
///
/// `config_arg` is the `--config` value: the default name searches the current
/// directory for the write profile's file, and any other value is that file.
pub(crate) fn local_target_path(
    config_arg: &Path,
    profile: &[String],
    write_profile: Option<&str>,
) -> Result<PathBuf> {
    let current_dir = std::env::current_dir()
        .map_err(|e| FnoxError::Config(format!("Failed to get current directory: {}", e)))?;
    // Only use auto-detection when --config is the clap default ("fnox.toml").
    // Any other value means the user explicitly chose a config file.
    if config_arg == Path::new(config::DEFAULT_CONFIG_FILENAME) {
        let write_profile = Config::resolve_write_profile(profile, write_profile)?;
        Ok(config::find_local_config(
            &current_dir,
            std::slice::from_ref(&write_profile),
        ))
    } else {
        Ok(current_dir.join(config_arg))
    }
}

/// The provider `fnox set` stores a value with: `explicit`, else the secret's
/// current provider, else `default_provider`. `None` means plain text.
pub(crate) fn storage_provider(
    config: &Config,
    write_profile: &str,
    explicit: Option<&str>,
    effective_secret: Option<&config::SecretConfig>,
) -> Result<Option<String>> {
    if let Some(provider) = explicit.or_else(|| effective_secret.and_then(|s| s.provider())) {
        return Ok(Some(provider.to_string()));
    }
    config.get_default_provider(&[write_profile.to_string()])
}

/// Whether a provider keeps a new value out of the config in plain text, by
/// encrypting it or storing it remotely
pub(crate) fn stores_securely(
    provider_config: &config::ProviderConfig,
    capabilities: &[ProviderCapability],
) -> bool {
    // The plain provider reports Encryption but stores values as they are
    !matches!(provider_config, config::ProviderConfig::Plain { .. })
        && (capabilities.contains(&ProviderCapability::Encryption)
            || capabilities.contains(&ProviderCapability::RemoteStorage))
}

/// Return whether a loaded secret came from the table this command will update.
fn secret_belongs_to_target(
    secret: &config::SecretConfig,
    target_path: &Path,
    write_profile: &str,
) -> bool {
    if secret.source_path.as_deref() != Some(target_path) {
        return false;
    }

    if write_profile == "default" {
        !secret.source_is_profile
    } else {
        secret.source_profile.as_deref() == Some(write_profile)
    }
}

/// Store a secret and add it to the config
///
/// Stores the value with a provider and records KEY in the config file in the
/// current directory, or the global config with `--global`. With an encryption
/// provider such as age, the ciphertext goes in the config. With a remote
/// provider such as 1Password or AWS Secrets Manager, the value is written to
/// the provider and the config records its key there. With no provider, the
/// value is stored in plain text.
///
/// The provider is `--provider`, else the secret's current provider, else
/// `default_provider`. When you omit VALUE, fnox reads piped stdin (trimming
/// surrounding whitespace) or prompts with hidden input. `--from-file` reads a
/// file verbatim, including trailing newlines. Passing only `--description`,
/// `--default`, or `--if-missing` updates those settings without asking for a
/// value.
#[derive(Debug, usage_rs::Args)]
#[usage(alias("s"))]
#[usage(
    example(
        "fnox set DATABASE_URL",
        header = "Prompt for a value with hidden input"
    ),
    example(
        "fnox set API_TOKEN --provider op",
        header = "Store a value with a specific provider"
    ),
    example(
        "fnox set SSH_KEY --from-file ~/.ssh/id_ed25519",
        header = "Store a file's contents verbatim"
    ),
    example(
        "printf '%s' \"$TOKEN\" | fnox set API_TOKEN",
        header = "Read the value from stdin"
    ),
    example(
        "fnox set API_TOKEN --generate --length 48",
        header = "Generate and store a random value"
    ),
    example(
        "fnox -P staging set DATABASE_URL",
        header = "Write to the staging profile"
    ),
    after_long_help = "See also:\n- Quick start: https://fnox.jdx.dev/guide/quick-start\n- Configuration reference: https://fnox.jdx.dev/reference/configuration"
)]
pub struct SetCommand {
    /// Secret name, used as the environment variable name
    pub key: Option<String>,

    /// Value to store; omit to read stdin or prompt
    ///
    /// A value passed as an argument appears in shell history and process
    /// listings. Prefer stdin or the prompt for sensitive values.
    pub value: Option<String>,

    /// Description to record with the secret
    #[usage(short = 'd', long)]
    pub description: Option<String>,

    /// Write to the global config file (`~/.config/fnox/config.toml`)
    #[usage(short = 'g', long)]
    pub global: bool,

    /// Name to store the value under at a remote provider (default: KEY)
    #[usage(short = 'k', long)]
    pub key_name: Option<String>,

    /// Show what would be written without storing anything
    #[usage(short = 'n', long)]
    pub dry_run: bool,

    /// Provider to store the value with (default: the secret's current provider,
    /// then `default_provider`)
    #[usage(short = 'p', long)]
    pub provider: Option<String>,

    /// Base64-encode the value before storing it
    #[usage(long)]
    pub base64_encode: bool,

    /// Fallback value to use when the secret cannot be resolved
    #[usage(long)]
    pub default: Option<String>,

    /// Store a file under the path it belongs at, instead of a secret
    ///
    /// Reads the current content of PATH (or `--from-file`) and records it under
    /// `[files]` in the global config, keyed by PATH. A file is never an
    /// environment variable; `fnox files write` puts it back at PATH.
    #[usage(long, conflicts = "key", value_hint = usage_rs::ValueHint::FilePath)]
    pub file: Option<PathBuf>,

    /// Replace an existing secret when generating
    #[usage(long, requires = "generate")]
    pub force: bool,

    /// Read the value from a UTF-8 file, verbatim
    #[usage(
        long,
        conflicts = "value",
        value_hint = usage_rs::ValueHint::FilePath
    )]
    pub from_file: Option<PathBuf>,

    /// Generate a random value instead of reading one
    ///
    /// Uses the OS random number generator. The value is stored through the
    /// normal provider path and is not printed unless you pass `--show`.
    /// Refuses to replace an existing secret unless you pass `--force`.
    #[usage(long, conflicts = "value", conflicts = "from_file")]
    pub generate: bool,

    /// Kind of value `--generate` creates
    #[usage(long, value_enum, default_value_t = GenerateKind::Password, default = "password", requires = "generate")]
    pub generate_type: GenerateKind,

    /// What to do when the secret cannot be resolved: `error`, `warn`, or `ignore`
    #[usage(long, value_enum)]
    pub if_missing: Option<IfMissing>,

    /// Length in characters of a generated value (default: 32; ignored for uuid; base64 cannot be 1 more than a multiple of 4)
    #[usage(long, requires = "generate")]
    pub length: Option<usize>,

    /// Print the generated value after storing it
    #[usage(long, requires = "generate")]
    pub show: bool,

    /// With `--file`, keep the stored content in this file, relative to the
    /// global config directory, instead of in the config
    #[usage(long, requires = "file")]
    pub source: Option<String>,
}

impl SetCommand {
    /// The secret name; `run_at` checks that it is set before anything reads it
    fn key(&self) -> &str {
        self.key.as_deref().unwrap_or_default()
    }

    /// `fnox set --file PATH`
    async fn run_file(&self, cli: &Cli, config: &Config, path: &Path) -> Result<()> {
        let unsupported = [
            ("VALUE", self.value.is_some()),
            ("--generate", self.generate),
            ("--base64-encode", self.base64_encode),
            ("--default", self.default.is_some()),
            ("--if-missing", self.if_missing.is_some()),
        ];
        if let Some((flag, _)) = unsupported.iter().find(|(_, set)| *set) {
            return Err(FnoxError::Config(format!(
                "{flag} does not apply to --file; a file is stored as it is"
            )));
        }
        crate::commands::files::set_file(
            cli,
            config,
            path,
            self.from_file.as_deref(),
            crate::commands::files::PutOptions {
                provider: self.provider.clone(),
                source: self.source.clone(),
                key_name: self.key_name.clone(),
                description: self.description.clone(),
                dry_run: self.dry_run,
            },
        )
        .await
    }

    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if let Some(path) = &self.file {
            return self.run_file(cli, &config, path).await;
        }
        let target_path = if self.global {
            Config::global_config_path()
        } else {
            let profile = Config::get_profiles(cli.profile.as_slice());
            local_target_path(&cli.config, &profile, cli.write_profile.as_deref())?
        };
        self.run_at(cli, config, target_path).await
    }

    /// Store the secret in `target_path` instead of the file `run` would pick
    pub async fn run_at(&self, cli: &Cli, config: Config, target_path: PathBuf) -> Result<()> {
        let profile = Config::get_profiles(cli.profile.as_slice());
        let stored = self
            .store_at(
                config,
                &profile,
                cli.write_profile.as_deref(),
                &target_path,
                false,
            )
            .await?;
        self.report(&stored, &target_path);
        Ok(())
    }

    /// Store the secret in `target_path` without printing anything.
    ///
    /// `profile` is the active profile list, as `Config::get_profiles` returns
    /// it. With `require_provider`, a value that would be stored in plain text
    /// (no provider, or one that neither encrypts nor stores remotely) is
    /// refused instead.
    pub(crate) async fn store_at(
        &self,
        mut config: Config,
        profile: &[String],
        write_profile: Option<&str>,
        target_path: &Path,
        require_provider: bool,
    ) -> Result<Stored> {
        if self.key.is_none() {
            return Err(FnoxError::Config(
                "Provide a secret name, or --file PATH to store a file".into(),
            ));
        }
        config::validate_secret_name(self.key())?;

        let write_profile = Config::resolve_write_profile(profile, write_profile)?;
        tracing::debug!(
            "Setting secret '{}' in profile '{}'",
            self.key(),
            write_profile
        );

        let write_profile_stack = vec![write_profile.clone()];

        // Check if we're only setting metadata (no actual secret value)
        let has_metadata =
            self.description.is_some() || self.if_missing.is_some() || self.default.is_some();

        // Get the secret value if provided
        let mut generated: Option<String> = None;
        let secret_value = if self.generate {
            let value = generate::generate(
                self.generate_type,
                self.length.unwrap_or(generate::DEFAULT_LENGTH),
            )?;
            generated = Some(value.clone());
            Some(value)
        } else if let Some(ref path) = self.from_file {
            Some(std::fs::read_to_string(path).map_err(|source| {
                FnoxError::SecretFileReadFailed {
                    path: path.clone(),
                    source,
                }
            })?)
        } else if let Some(ref v) = self.value {
            // Value provided as argument
            Some(v.clone())
        } else if !atty::is(atty::Stream::Stdin) {
            // Read from stdin if piped
            tracing::debug!("Reading secret value from stdin");
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|source| FnoxError::StdinReadFailed { source })?;
            let value = buffer.trim().to_string();
            if value.is_empty() && has_metadata && self.key_name.is_none() {
                // Nothing piped and only metadata is being set
                None
            } else {
                Some(value)
            }
        } else if has_metadata && self.key_name.is_none() {
            // Only metadata is being set, no secret value needed
            None
        } else {
            // Interactive terminal - prompt for value
            let value = demand::Input::new("Enter secret value")
                .prompt("Secret value: ")
                .password(true)
                .run()
                .map_err(|e| FnoxError::Config(format!("Failed to read input: {}", e)))?;
            Some(value)
        };

        let effective_secret = config
            .get_secret(&write_profile_stack, self.key())?
            .cloned();
        let existing_secret = effective_secret
            .as_ref()
            .filter(|secret| secret_belongs_to_target(secret, target_path, &write_profile))
            .cloned();

        if self.generate
            && !self.force
            && (effective_secret.is_some()
                || Config::target_has_secret(self.key(), &write_profile, target_path)?)
        {
            return Err(FnoxError::Config(format!(
                "Secret '{}' already exists; pass --force to replace it with a generated value",
                self.key()
            )));
        }

        let provider_name_to_use = storage_provider(
            &config,
            &write_profile,
            self.provider.as_deref(),
            effective_secret.as_ref(),
        )?;
        if require_provider && provider_name_to_use.is_none() {
            return Err(FnoxError::Config(format!(
                "Secret '{}' has no provider and no default_provider is set; refusing to store it in plain text",
                self.key()
            )));
        }

        // Check if secret should be base64 encoded
        let secret_value = if self.base64_encode {
            secret_value
                .as_ref()
                .map(|value| data_encoding::BASE64.encode(value.as_bytes()))
        } else {
            secret_value
        };

        // Handle provider-specific behavior (before we get mutable borrow)
        let (encrypted_value, remote_key_name) = if let Some(ref value) = secret_value {
            if let Some(ref provider_name) = provider_name_to_use {
                // Get the provider config
                let providers = config.get_providers(&write_profile_stack)?;
                if let Some(provider_config) = providers.get(provider_name) {
                    // Get the provider (resolving any secret refs) and check its capabilities
                    let provider = crate::providers::get_provider_resolved(
                        &config,
                        &write_profile_stack,
                        provider_name,
                        provider_config,
                    )
                    .await?;
                    let capabilities = provider.capabilities();

                    // Ensure the provider has at least one capability
                    if capabilities.is_empty() {
                        return Err(FnoxError::Config(format!(
                            "Provider '{}' has no capabilities defined",
                            provider_name
                        )));
                    }

                    if require_provider && !stores_securely(provider_config, &capabilities) {
                        return Err(FnoxError::Config(format!(
                            "Provider '{provider_name}' would leave '{}' in plain text in the config; refusing to store it",
                            self.key()
                        )));
                    }

                    let is_encryption_provider =
                        capabilities.contains(&crate::providers::ProviderCapability::Encryption);
                    let is_remote_storage_provider =
                        capabilities.contains(&crate::providers::ProviderCapability::RemoteStorage);

                    if is_encryption_provider {
                        tracing::debug!(
                            "Encrypting secret value with provider '{}'",
                            provider_name
                        );

                        if self.dry_run {
                            // In dry-run mode, skip actual encryption
                            (Some("<encrypted>".to_string()), None)
                        } else {
                            // Encrypt with the provider — fail on error rather than
                            // silently storing plaintext
                            let encrypted = provider.encrypt(value).await?;
                            (Some(encrypted), None)
                        }
                    } else if is_remote_storage_provider {
                        tracing::debug!(
                            "Storing secret '{}' in remote provider '{}'",
                            self.key(),
                            provider_name
                        );

                        let key_name = resolve_remote_key_name(
                            self.key(),
                            self.key_name.as_deref(),
                            existing_secret.as_ref(),
                            provider_name,
                        );

                        if self.dry_run {
                            // In dry-run mode, skip actual remote storage
                            (None, Some(key_name.to_string()))
                        } else {
                            // Use the already-resolved provider to store the secret
                            let stored_key = provider.put_secret(key_name, value).await?;

                            // Store just the key name (without prefix) in config
                            (None, Some(stored_key))
                        }
                    } else {
                        // Not an encryption or remote storage provider
                        (None, None)
                    }
                } else {
                    return Err(FnoxError::Config(format!(
                        "Provider '{}' not found in configuration",
                        provider_name
                    )));
                }
            } else {
                // No provider specified or available
                (None, None)
            }
        } else {
            (None, None)
        };

        // Now update the config — use the resolved write_profile, not the
        // full stack, so the secret lands in the correct TOML section.
        let profile_secrets = config.get_secrets_mut(&write_profile_stack);

        // Updating an inherited secret creates a local override. Seed it from
        // the effective secret so the override retains the inherited settings
        // (and the value/provider, for a metadata-only update) instead of
        // shadowing it with an empty entry.
        let inherited_secret = existing_secret
            .is_none()
            .then(|| effective_secret.clone())
            .flatten();
        let secret_config = profile_secrets
            .entry(self.key().to_string())
            .or_insert_with(|| inherited_secret.unwrap_or_default());

        // Update metadata
        if let Some(ref desc) = self.description {
            secret_config.description = Some(desc.clone());
        }

        if let Some(if_missing) = self.if_missing {
            secret_config.if_missing = Some(if_missing);
        }

        if let Some(ref default) = self.default {
            secret_config.default = Some(default.clone());
        }

        // Set the provider if explicitly specified
        if let Some(ref provider) = self.provider {
            secret_config.set_provider(Some(provider.clone()));
        } else if provider_name_to_use.is_some() && secret_config.provider().is_none() {
            // If we have a default provider and the secret doesn't already have one,
            // store it explicitly for clarity
            secret_config.set_provider(provider_name_to_use.clone());
        }

        if secret_value.is_some() {
            // A new value must not leave a stale `fnox sync` cache that would
            // take precedence over it.
            secret_config.sync = None;
        }

        if let Some(ref value) = secret_value {
            // Priority order: remote key name, encrypted value, then plaintext
            if let Some(remote_key) = remote_key_name {
                // Store the key name for remote storage providers
                secret_config.set_value(Some(remote_key));
            } else if let Some(encrypted) = encrypted_value {
                // Store encrypted value for encryption providers
                secret_config.set_value(Some(encrypted));
            } else if provider_name_to_use.is_some() {
                // Provider specified or default provider available (but not an encryption/remote provider)
                secret_config.set_value(Some(value.clone()));
            } else {
                // No provider specified or available, store as default value
                secret_config.set_value(Some(value.clone()));
                secret_config.default = Some(value.clone());
            }
        }

        let secret_config = profile_secrets.get(self.key()).unwrap().clone();
        let _ = profile_secrets; // Release the mutable borrow

        // Save the secret to the appropriate config file
        // Configs selected explicitly may live under `.config/`. Create the
        // target's parent before writing, including for project configs.
        if !self.dry_run {
            if let Some(parent) = target_path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|e| {
                    FnoxError::Config(format!(
                        "Failed to create config directory '{}': {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
            config.save_secret_to_source(
                self.key(),
                &secret_config,
                &write_profile,
                target_path,
            )?;
        }

        Ok(Stored {
            write_profile,
            secret: secret_config,
            generated,
        })
    }

    /// Print what `store_at` did, or would do with `--dry-run`
    fn report(&self, stored: &Stored, target_path: &Path) {
        let Stored {
            write_profile,
            secret: secret_config,
            generated,
        } = stored;
        if self.dry_run {
            // Show what would be done
            let dry_run_label = console::style("[dry-run]").yellow().bold();
            let styled_key = console::style(self.key()).cyan();
            let styled_profile = console::style(write_profile).magenta();
            let styled_path = console::style(target_path.display()).dim();
            let global_suffix = if self.global { " (global)" } else { "" };

            if write_profile == "default" {
                println!(
                    "{dry_run_label} Would set secret {styled_key}{global_suffix} in {styled_path}"
                );
            } else {
                println!(
                    "{dry_run_label} Would set secret {styled_key} in profile {styled_profile}{global_suffix} in {styled_path}"
                );
            }

            // Show the config that would be written
            if let Some(provider) = secret_config.provider() {
                println!("  provider: {}", console::style(provider).green());
            }
            if let Some(value) = secret_config.value().filter(|_| generated.is_none()) {
                // Use character-aware truncation to avoid panicking on multi-byte UTF-8
                let display_value = if value.chars().count() > 50 {
                    format!("{}...", value.chars().take(50).collect::<String>())
                } else {
                    value.to_string()
                };
                println!("  value: {}", console::style(display_value).dim());
            }
            if let Some(value) = generated.as_ref().filter(|_| self.show) {
                println!("  generated: {}", console::style(value).dim());
            }
            if let Some(ref desc) = secret_config.description {
                println!("  description: {}", console::style(desc).dim());
            }
            if let Some(default) = secret_config
                .default
                .as_ref()
                .filter(|_| generated.is_none())
            {
                println!("  default: {}", console::style(default).dim());
            }
            if let Some(if_missing) = secret_config.if_missing {
                println!(
                    "  if_missing: {}",
                    console::style(format!("{:?}", if_missing).to_lowercase()).dim()
                );
            }
        } else {
            let check = console::style("✓").green();
            let styled_key = console::style(self.key()).cyan();
            let styled_profile = console::style(write_profile).magenta();
            let global_suffix = if self.global { " (global)" } else { "" };
            if write_profile == "default" {
                println!("{check} Set secret {styled_key}{global_suffix}");
            } else {
                println!(
                    "{check} Set secret {styled_key} in profile {styled_profile}{global_suffix}"
                );
            }
            if let Some(value) = generated {
                if self.show {
                    println!("{value}");
                } else {
                    println!(
                        "  generated a random {} value (use --show to print it)",
                        self.generate_type
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(provider: &str, value: &str) -> config::SecretConfig {
        let mut secret = config::SecretConfig::default();
        secret.set_provider(Some(provider.to_string()));
        secret.set_value(Some(value.to_string()));
        secret
    }

    #[test]
    fn remote_key_name_prefers_explicit_key_name() {
        let existing = secret("gcp", "existing-name");

        assert_eq!(
            resolve_remote_key_name("ENV_NAME", Some("explicit-name"), Some(&existing), "gcp"),
            "explicit-name"
        );
    }

    #[test]
    fn remote_key_name_reuses_existing_value_for_same_provider() {
        let existing = secret("gcp", "existing-name");

        assert_eq!(
            resolve_remote_key_name("ENV_NAME", None, Some(&existing), "gcp"),
            "existing-name"
        );
    }

    #[test]
    fn remote_key_name_uses_env_key_when_switching_providers() {
        let existing = secret("aws", "existing-name");

        assert_eq!(
            resolve_remote_key_name("ENV_NAME", None, Some(&existing), "gcp"),
            "ENV_NAME"
        );
    }

    #[test]
    fn inherited_secret_does_not_supply_remote_key_name() {
        let mut existing = secret("gcp", "shared-name");
        existing.source_path = Some("/parent/fnox.toml".into());

        assert!(!secret_belongs_to_target(
            &existing,
            Path::new("/child/fnox.toml"),
            "default"
        ));
    }

    #[test]
    fn profile_file_secret_belongs_to_named_profile_target() {
        let mut existing = secret("plain", "value");
        existing.source_path = Some("/project/fnox.app.toml".into());
        existing.source_is_profile = true;
        existing.source_profile = Some("app".to_string());

        assert!(secret_belongs_to_target(
            &existing,
            Path::new("/project/fnox.app.toml"),
            "app"
        ));
    }
}
