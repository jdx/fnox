use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::{OptionProviderSecretRef, ResolvedStringOrProviderRef};
use async_trait::async_trait;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const BATCH_VALUE_PREFIX: &str = "fnox-age-batch-v1:";
const BATCH_KEY_CONTEXT: &[u8] = b"fnox-age-batch-v1";

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

pub struct AgeEncryptionProvider {
    recipients: Vec<String>,
    key_file: Option<PathBuf>,
    identity: OptionProviderSecretRef,
    named_identities: Option<NamedIdentities>,
    config: Option<Arc<crate::config::Config>>,
    profile: Vec<String>,
    provider_name: String,
    identity_cycle_guard: Option<AgeIdentityCycleGuard>,
}

struct NamedIdentities {
    identities: indexmap::IndexMap<String, ResolvedStringOrProviderRef>,
    default_identity: Option<String>,
}

/// The key file to decrypt with, and the `identity` reference to use alongside it.
pub(crate) struct KeySelection {
    pub key_file: Option<String>,
    pub identity: OptionProviderSecretRef,
    /// The selected named identity is a `{ provider, value }` entry.
    pub named_provider_ref: bool,
}

/// Picks the key file to decrypt with. A named identity (`FNOX_AGE_IDENTITY`, else
/// `default_identity`) replaces `key_file` and the `identity` reference: a path entry becomes
/// the key file, and a `{ provider, value }` entry becomes the `identity` reference. An inline
/// `FNOX_AGE_KEY` outranks all of them, so it skips the selection.
///
/// Age environment variables are read on every call: the daemon changes its environment per request.
pub(crate) fn select_key_file(
    provider_name: &str,
    key_file: Option<String>,
    identity: OptionProviderSecretRef,
    identities: &indexmap::IndexMap<String, ResolvedStringOrProviderRef>,
    default_identity: Option<&str>,
) -> Result<KeySelection> {
    select_key_file_with(
        provider_name,
        key_file,
        identity,
        identities,
        default_identity,
        env::fnox_age_identity().as_deref(),
        env::fnox_age_key().is_some(),
    )
}

fn select_key_file_with(
    provider_name: &str,
    key_file: Option<String>,
    identity: OptionProviderSecretRef,
    identities: &indexmap::IndexMap<String, ResolvedStringOrProviderRef>,
    default_identity: Option<&str>,
    env_identity: Option<&str>,
    inline_key_set: bool,
) -> Result<KeySelection> {
    let unchanged = KeySelection {
        key_file: key_file.clone(),
        identity: identity.clone(),
        named_provider_ref: false,
    };
    if inline_key_set {
        return Ok(unchanged);
    }
    let Some(name) = env_identity.or(default_identity) else {
        return Ok(unchanged);
    };
    match identities.get(name) {
        Some(ResolvedStringOrProviderRef::String(path)) => Ok(KeySelection {
            key_file: Some(path.clone()),
            identity: OptionProviderSecretRef::none(),
            named_provider_ref: false,
        }),
        Some(ResolvedStringOrProviderRef::Provider(identity)) => Ok(KeySelection {
            key_file: None,
            identity: OptionProviderSecretRef(Some(identity.clone())),
            named_provider_ref: true,
        }),
        None => Err(FnoxError::Config(format!(
            "Age identity '{name}' is not defined in provider '{provider_name}' (available: {})",
            identities.keys().cloned().collect::<Vec<_>>().join(", ")
        ))),
    }
}

impl AgeEncryptionProvider {
    pub fn new(
        recipients: Vec<String>,
        key_file: Option<String>,
        identity: OptionProviderSecretRef,
        identities: indexmap::IndexMap<String, ResolvedStringOrProviderRef>,
        default_identity: Option<String>,
    ) -> Result<Self> {
        let selected = select_key_file(
            "age",
            key_file.clone(),
            identity.clone(),
            &identities,
            default_identity.as_deref(),
        )?;
        // Without a config there is no provider to resolve the reference through.
        if selected.named_provider_ref {
            return Err(FnoxError::Config(
                "A provider-backed named age identity needs the config to resolve it".to_string(),
            ));
        }
        Ok(Self {
            recipients,
            key_file: key_file.map(|k| crate::config_path::resolve_relative_to_file(&k, None)),
            identity,
            named_identities: Some(NamedIdentities {
                identities: identities
                    .into_iter()
                    .map(|(name, identity)| {
                        let identity = match identity {
                            ResolvedStringOrProviderRef::String(path) => {
                                ResolvedStringOrProviderRef::String(
                                    crate::config_path::resolve_string_relative_to_file(path, None),
                                )
                            }
                            identity => identity,
                        };
                        (name, identity)
                    })
                    .collect(),
                default_identity,
            }),
            config: None,
            profile: vec!["default".to_string()],
            provider_name: "age".to_string(),
            identity_cycle_guard: None,
        })
    }

    pub fn new_with_config(
        recipients: Vec<String>,
        key_file: Option<String>,
        identity: OptionProviderSecretRef,
        config: Arc<crate::config::Config>,
        profile: Vec<String>,
        provider_name: String,
        identity_cycle_guard: Option<AgeIdentityCycleGuard>,
    ) -> Result<Self> {
        Ok(Self {
            recipients,
            key_file: key_file.map(|k| crate::config_path::resolve_relative_to_file(&k, None)),
            identity,
            named_identities: None,
            config: Some(config),
            profile,
            provider_name,
            identity_cycle_guard,
        })
    }

    pub(crate) fn with_named_identities(
        mut self,
        identities: indexmap::IndexMap<String, ResolvedStringOrProviderRef>,
        default_identity: Option<String>,
    ) -> Result<Self> {
        select_key_file(
            &self.provider_name,
            None,
            self.identity.clone(),
            &identities,
            default_identity.as_deref(),
        )?;
        self.named_identities = Some(NamedIdentities {
            identities,
            default_identity,
        });
        Ok(self)
    }

    fn selected_identity(&self) -> Result<KeySelection> {
        let key_file = self
            .key_file
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());
        let Some(named) = &self.named_identities else {
            return Ok(KeySelection {
                key_file,
                identity: self.identity.clone(),
                named_provider_ref: false,
            });
        };
        select_key_file_with(
            &self.provider_name,
            key_file,
            self.identity.clone(),
            &named.identities,
            named.default_identity.as_deref(),
            env::fnox_age_identity().as_deref(),
            false,
        )
    }

    async fn resolve_provider_identity(
        &self,
        ciphertext: &str,
        selected_identity: &OptionProviderSecretRef,
    ) -> Result<Option<String>> {
        let Some(identity) = selected_identity.as_ref() else {
            return Ok(None);
        };

        if identity.provider == self.provider_name {
            return Err(FnoxError::ProviderConfigCycle {
                provider: self.provider_name.clone(),
                cycle: format!("{} -> {}", self.provider_name, identity.provider),
            });
        }

        let Some(config) = self.config.as_ref() else {
            return Err(FnoxError::Config(
                "Cannot resolve age identity provider reference without config context".to_string(),
            ));
        };

        let identity_cycle_guard = self.identity_cycle_guard.clone().unwrap_or_default();
        let _guard = identity_cycle_guard.enter(&self.provider_name)?;
        let _decrypting = identity_cycle_guard.mark_decrypting(ciphertext);
        let mut ctx = crate::providers::resolver::ResolutionContext::new();
        crate::providers::resolver::resolve_provider_ref_with_identity_cycle_guard(
            config,
            &self.profile,
            selected_identity,
            &mut ctx,
            identity_cycle_guard,
        )
        .await
    }

    fn parse_batch_value(value: &str) -> Option<(&str, &str)> {
        let value = value.strip_prefix(BATCH_VALUE_PREFIX)?;
        value.split_once(':')
    }

    async fn decrypt_batch_key(&self, wrapped_key: &str) -> Result<Vec<u8>> {
        use base64::Engine;

        let encoded_key = self.decrypt_age_value(wrapped_key).await?;
        let key = base64::engine::general_purpose::STANDARD
            .decode(encoded_key)
            .map_err(|e| FnoxError::AgeDecryptionFailed {
                details: format!("Failed to decode batch key: {e}"),
            })?;
        if key.len() != 32 {
            return Err(FnoxError::AgeDecryptionFailed {
                details: format!(
                    "Invalid batch key length: expected 32 bytes, got {}",
                    key.len()
                ),
            });
        }
        Ok(key)
    }
}

#[derive(Clone, Default)]
pub struct AgeIdentityCycleGuard {
    resolving: Arc<Mutex<Vec<String>>>,
    decrypting: Arc<Mutex<Vec<String>>>,
}

impl AgeIdentityCycleGuard {
    fn is_reentrant(&self, provider_name: &str, ciphertext: &str) -> bool {
        let contains = |list: &Mutex<Vec<String>>, item: &str| {
            list.lock()
                .is_ok_and(|list| list.iter().any(|entry| entry == item))
        };
        contains(&self.resolving, provider_name) || contains(&self.decrypting, ciphertext)
    }

    fn mark_decrypting(&self, ciphertext: &str) -> AgeIdentityCycleEntry {
        if let Ok(mut decrypting) = self.decrypting.lock() {
            decrypting.push(ciphertext.to_string());
        }
        AgeIdentityCycleEntry {
            item: ciphertext.to_string(),
            list: self.decrypting.clone(),
        }
    }

    fn enter(&self, provider_name: &str) -> Result<AgeIdentityCycleEntry> {
        let mut resolving = self
            .resolving
            .lock()
            .map_err(|_| FnoxError::Config("Age identity cycle guard lock poisoned".to_string()))?;

        if let Some(start) = resolving.iter().position(|name| name == provider_name) {
            let mut cycle = resolving[start..].to_vec();
            cycle.push(provider_name.to_string());
            return Err(FnoxError::ProviderConfigCycle {
                provider: provider_name.to_string(),
                cycle: cycle.join(" -> "),
            });
        }

        resolving.push(provider_name.to_string());

        Ok(AgeIdentityCycleEntry {
            item: provider_name.to_string(),
            list: self.resolving.clone(),
        })
    }
}

struct AgeIdentityCycleEntry {
    item: String,
    list: Arc<Mutex<Vec<String>>>,
}

impl Drop for AgeIdentityCycleEntry {
    fn drop(&mut self) {
        if let Ok(mut list) = self.list.lock()
            && let Some(index) = list.iter().rposition(|entry| entry == &self.item)
        {
            list.remove(index);
        }
    }
}

#[async_trait]
impl crate::providers::Provider for AgeEncryptionProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String> {
        use std::io::Write;

        if self.recipients.is_empty() {
            return Err(FnoxError::AgeNotConfigured);
        }

        // Parse recipients - try SSH, native age, then plugin formats
        let mut parsed_recipients: Vec<Box<dyn age::Recipient + Send + Sync>> = Vec::new();
        let mut plugin_recipients: Vec<age::plugin::Recipient> = Vec::new();

        for recipient in &self.recipients {
            // Try parsing as SSH recipient first
            if let Ok(ssh_recipient) = recipient.parse::<age::ssh::Recipient>() {
                parsed_recipients.push(Box::new(ssh_recipient));
                continue;
            }

            // Try native age recipient
            if let Ok(age_recipient) = recipient.parse::<age::x25519::Recipient>() {
                parsed_recipients.push(Box::new(age_recipient));
                continue;
            }

            // Fall back to plugin recipient, e.g. age-plugin-yubikey: age1yubikey1...
            match recipient.parse::<age::plugin::Recipient>() {
                Ok(plugin_recipient) => plugin_recipients.push(plugin_recipient),
                Err(e) => {
                    return Err(FnoxError::AgeEncryptionFailed {
                        details: format!("Failed to parse recipient '{}': {}", recipient, e),
                    });
                }
            }
        }

        // Build one plugin driver per distinct plugin name. RecipientPluginV1
        // filters the recipient list by plugin name internally, so we pass the
        // full list and spawn the matching `age-plugin-*` binary from $PATH.
        let plugin_names: std::collections::BTreeSet<String> = plugin_recipients
            .iter()
            .map(|r| r.plugin().to_string())
            .collect();
        for plugin_name in plugin_names {
            let plugin = age::plugin::RecipientPluginV1::new(
                &plugin_name,
                &plugin_recipients,
                &[],
                age::cli_common::UiCallbacks,
            )
            .map_err(|e| FnoxError::AgeEncryptionFailed {
                details: format!(
                    "Failed to initialize age plugin 'age-plugin-{}' \
                     (is it installed and on your PATH?): {}",
                    plugin_name, e
                ),
            })?;
            parsed_recipients.push(Box::new(plugin));
        }

        // Every recipient is parsed into `parsed_recipients` (directly or via a
        // plugin driver) or returns early on failure, and the empty-input case
        // is rejected at the top of the function, so this is always non-empty.
        debug_assert!(
            !parsed_recipients.is_empty(),
            "non-empty recipients must yield at least one parsed recipient"
        );

        // Create encryptor with parsed recipients. With plugin recipients this
        // talks to the plugin binary eagerly, so it can fail for reasons beyond
        // an empty recipient list (which we already ruled out above).
        let encryptor = age::Encryptor::with_recipients(
            parsed_recipients
                .iter()
                .map(|r| r.as_ref() as &dyn age::Recipient),
        )
        .map_err(|e| FnoxError::AgeEncryptionFailed {
            details: format!("Failed to initialize age encryptor: {}", e),
        })?;

        // Encrypt the plaintext
        let mut encrypted = vec![];
        let mut writer =
            encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| FnoxError::AgeEncryptionFailed {
                    details: format!("Failed to create encrypted writer: {}", e),
                })?;

        writer
            .write_all(plaintext.as_bytes())
            .map_err(|e| FnoxError::AgeEncryptionFailed {
                details: format!("Failed to write plaintext: {}", e),
            })?;

        writer
            .finish()
            .map_err(|e| FnoxError::AgeEncryptionFailed {
                details: format!("Failed to finalize encryption: {}", e),
            })?;

        // Base64 encode the encrypted output
        use base64::Engine;
        let encrypted_base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        Ok(encrypted_base64)
    }

    async fn encrypt_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        use base64::Engine;

        if secrets.is_empty() {
            return HashMap::new();
        }

        let mut batch_key = [0u8; 32];
        rand::fill(&mut batch_key);
        let encoded_key = base64::engine::general_purpose::STANDARD.encode(batch_key);
        let wrapped_key = match self.encrypt(&encoded_key).await {
            Ok(value) => value,
            Err(error) => {
                let message = error.to_string();
                return secrets
                    .iter()
                    .map(|(key, _)| {
                        (
                            key.clone(),
                            Err(FnoxError::AgeEncryptionFailed {
                                details: message.clone(),
                            }),
                        )
                    })
                    .collect();
            }
        };

        secrets
            .iter()
            .map(|(key, plaintext)| {
                let encrypted =
                    super::hw_encrypt::encrypt(&batch_key, BATCH_KEY_CONTEXT, plaintext).map(
                        |ciphertext| format!("{BATCH_VALUE_PREFIX}{wrapped_key}:{ciphertext}"),
                    );
                (key.clone(), encrypted)
            })
            .collect()
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        if let Some((wrapped_key, ciphertext)) = Self::parse_batch_value(value) {
            let batch_key = self.decrypt_batch_key(wrapped_key).await?;
            return super::hw_encrypt::decrypt(&batch_key, BATCH_KEY_CONTEXT, ciphertext);
        }

        self.decrypt_age_value(value).await
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let mut results = HashMap::with_capacity(secrets.len());
        let mut batch_keys: HashMap<String, Result<Vec<u8>>> = HashMap::new();

        for (key, value) in secrets {
            let result = if let Some((wrapped_key, ciphertext)) = Self::parse_batch_value(value) {
                if !batch_keys.contains_key(wrapped_key) {
                    batch_keys.insert(
                        wrapped_key.to_string(),
                        self.decrypt_batch_key(wrapped_key).await,
                    );
                }
                match batch_keys.get(wrapped_key).expect("batch key was inserted") {
                    Ok(batch_key) => {
                        super::hw_encrypt::decrypt(batch_key, BATCH_KEY_CONTEXT, ciphertext)
                    }
                    Err(error) => Err(FnoxError::AgeDecryptionFailed {
                        details: error.to_string(),
                    }),
                }
            } else {
                self.decrypt_age_value(value).await
            };
            results.insert(key.clone(), result);
        }

        results
    }
}

type DecryptCells = HashMap<(String, Option<blake3::Hash>), Arc<tokio::sync::OnceCell<String>>>;

tokio::task_local! {
    static DECRYPT_SCOPE: Arc<Mutex<DecryptCells>>;
}

/// Shares age decrypts of a ciphertext within one request so PIN-backed identities prompt once.
pub async fn with_decrypt_scope<F: std::future::Future>(fut: F) -> F::Output {
    if DECRYPT_SCOPE.try_with(|_| ()).is_ok() {
        fut.await
    } else {
        DECRYPT_SCOPE.scope(Arc::default(), fut).await
    }
}

async fn decrypt_once<F, Fut>(
    ciphertext: &str,
    inline_key: Option<&str>,
    decrypt: F,
) -> Result<String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    let Ok(cells) = DECRYPT_SCOPE.try_with(Arc::clone) else {
        return decrypt().await;
    };
    let cell = cells
        .lock()
        .unwrap()
        .entry((
            ciphertext.to_string(),
            inline_key.map(|key| blake3::hash(key.as_bytes())),
        ))
        .or_default()
        .clone();
    cell.get_or_try_init(decrypt).await.cloned()
}

impl AgeEncryptionProvider {
    async fn decrypt_age_value(&self, value: &str) -> Result<String> {
        let inline_key = env::fnox_age_key();
        // Re-entered from an identity lookup on this chain (same provider or same
        // ciphertext): waiting on the outer, unfinished decrypt would never return.
        if self
            .identity_cycle_guard
            .as_ref()
            .is_some_and(|guard| guard.is_reentrant(&self.provider_name, value))
        {
            return self
                .decrypt_age_value_uncached(value, inline_key.as_deref())
                .await;
        }
        decrypt_once(value, inline_key.as_deref(), || {
            self.decrypt_age_value_uncached(value, inline_key.as_deref())
        })
        .await
    }

    async fn decrypt_age_value_uncached(
        &self,
        value: &str,
        inline_key: Option<&str>,
    ) -> Result<String> {
        // value contains the encrypted blob (might be base64 encoded or raw)

        // Try to decode as base64 first, if that fails, treat as raw bytes
        let encrypted_bytes =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value) {
                Ok(bytes) => bytes,
                Err(_) => {
                    // Not base64 encoded, treat as raw bytes
                    value.as_bytes().to_vec()
                }
            };

        // Priority for identity:
        // 1. FNOX_AGE_KEY env var (inline key content)
        // 2. Selected named identity, then provider identity/key_file
        // 3. Settings age_key_file (from CLI flag - deprecated)
        // 4. Default path (~/.config/fnox/age.txt)
        let (provider_identity, key_file) = if inline_key.is_none() {
            let selected = self.selected_identity()?;
            (
                self.resolve_provider_identity(value, &selected.identity)
                    .await?,
                selected.key_file,
            )
        } else {
            (None, None)
        };
        let (identity_content, key_file_path_opt) = if let Some(age_key) = inline_key {
            // Use the key directly from the environment variable
            (age_key.to_string(), None)
        } else if let Some(identity) = provider_identity {
            (identity, None)
        } else {
            // Determine which key file to use
            let key_file_path = if let Some(ref config_key_file) = key_file {
                // Use key file from provider config
                crate::config_path::resolve_relative_to_file(config_key_file, None)
            } else {
                // Get settings which merges CLI flags, env vars, and defaults
                let settings = crate::settings::Settings::get();

                if let Some(ref age_key_file) = settings.age_key_file {
                    // Use age key file from settings (CLI flag or env var - deprecated)
                    age_key_file.clone()
                } else {
                    // Try default path
                    let default_key_path = env::FNOX_CONFIG_DIR.join("age.txt");
                    if !default_key_path.exists() {
                        return Err(FnoxError::AgeIdentityNotFound {
                            path: default_key_path,
                        });
                    }
                    default_key_path
                }
            };

            // Load identity file content
            let bytes =
                std::fs::read(&key_file_path).map_err(|e| FnoxError::AgeIdentityReadFailed {
                    path: key_file_path.clone(),
                    source: e,
                })?;

            let content = if is_age_encrypted(&bytes) {
                decrypt_identity_file(&key_file_path, &bytes)?
            } else {
                String::from_utf8(bytes).map_err(|e| FnoxError::AgeIdentityReadFailed {
                    path: key_file_path.clone(),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                })?
            };

            (content, Some(key_file_path))
        };

        // Try parsing as SSH identity first, then fall back to age identity file
        let identities = {
            let mut cursor = std::io::Cursor::new(identity_content.as_bytes());

            // First try to parse as SSH identity
            match age::ssh::Identity::from_buffer(
                &mut cursor,
                key_file_path_opt
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string()),
            ) {
                Ok(ssh_identity) => {
                    // SSH identity parsed successfully
                    vec![Box::new(ssh_identity) as Box<dyn age::Identity + Send + Sync>]
                }
                Err(_) => {
                    // Not an SSH identity, try age identity file. Setting
                    // callbacks lets `into_identities` construct plugin
                    // identities (e.g. AGE-PLUGIN-YUBIKEY-1...) by driving the
                    // matching `age-plugin-*` binary for PIN/touch prompts.
                    cursor.set_position(0);
                    age::IdentityFile::from_buffer(cursor)
                        .map_err(|e| FnoxError::AgeIdentityParseFailed {
                            details: e.to_string(),
                        })?
                        .with_callbacks(age::cli_common::UiCallbacks)
                        .into_identities()
                        .map_err(|e| FnoxError::AgeIdentityParseFailed {
                            details: e.to_string(),
                        })?
                }
            }
        };

        let decryptor = age::Decryptor::new(encrypted_bytes.as_slice()).map_err(|e| {
            FnoxError::AgeDecryptionFailed {
                details: format!("Failed to create decryptor: {}", e),
            }
        })?;

        let mut reader = decryptor
            .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
            .map_err(|e| FnoxError::AgeDecryptionFailed {
                details: e.to_string(),
            })?;

        let mut decrypted = vec![];
        reader
            .read_to_end(&mut decrypted)
            .map_err(|e| FnoxError::AgeDecryptionFailed {
                details: format!("Failed to read decrypted data: {}", e),
            })?;

        String::from_utf8(decrypted).map_err(|e| FnoxError::AgeDecryptionFailed {
            details: format!("Failed to decode UTF-8: {}", e),
        })
    }
}

/// Identity files decrypted with a prompted passphrase, so one run asks once per file.
/// Keyed by canonical path; the encrypted bytes are kept so an edited file is not served stale.
type DecryptedIdentities = HashMap<PathBuf, (Vec<u8>, String)>;

static DECRYPTED_IDENTITIES: std::sync::LazyLock<Mutex<DecryptedIdentities>> =
    std::sync::LazyLock::new(Default::default);

/// True when the bytes are an age-encrypted file (binary or ASCII-armored), such as
/// the output of `age-keygen | age -p`.
fn is_age_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(b"age-encryption.org/v1\n")
        || bytes.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
}

fn identity_auth_error(path: &std::path::Path, details: String, hint: &str) -> FnoxError {
    FnoxError::ProviderAuthFailed {
        provider: "age".to_string(),
        details: format!("identity file {}: {details}", path.display()),
        hint: hint.to_string(),
        url: "https://fnox.jdx.dev/providers/age".to_string(),
    }
}

/// Decrypt a passphrase-encrypted identity file, prompting for the passphrase.
fn decrypt_identity_file(path: &std::path::Path, bytes: &[u8]) -> Result<String> {
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut cache = DECRYPTED_IDENTITIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((cached_bytes, content)) = cache.get(&key)
        && cached_bytes.as_slice() == bytes
    {
        return Ok(content.clone());
    }
    if env::is_non_interactive() {
        return Err(identity_auth_error(
            path,
            "it is passphrase-protected and no terminal is available to prompt".to_string(),
            "Run in a terminal to enter the passphrase, or decrypt the identity and set FNOX_AGE_KEY",
        ));
    }
    let passphrase =
        rpassword::prompt_password(format!("Passphrase for age identity {}: ", path.display()))
            .map_err(|e| {
                identity_auth_error(
                    path,
                    format!("could not read passphrase from terminal: {e}"),
                    "Run in a terminal to enter the passphrase",
                )
            })?;
    let content = decrypt_with_passphrase(bytes, passphrase).map_err(|details| {
        identity_auth_error(path, details, "Check the passphrase and try again")
    })?;
    cache.insert(key, (bytes.to_vec(), content.clone()));
    Ok(content)
}

fn decrypt_with_passphrase(
    bytes: &[u8],
    passphrase: String,
) -> std::result::Result<String, String> {
    let reader = age::armor::ArmoredReader::new(bytes);
    let decryptor = age::Decryptor::new(reader).map_err(|e| e.to_string())?;
    let identity = age::scrypt::Identity::new(age::secrecy::SecretString::from(passphrase));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| e.to_string())?;
    let mut out = vec![];
    reader.read_to_end(&mut out).map_err(|e| e.to_string())?;
    String::from_utf8(out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;
    use age::secrecy::ExposeSecret;

    #[test]
    fn select_key_file_uses_named_identity() {
        let path = |p: &str| ResolvedStringOrProviderRef::String(p.to_string());
        let fido2 = crate::providers::secret_ref::ProviderSecretRef {
            provider: "fido2".to_string(),
            value: "wrapped".to_string(),
        };
        let identities: indexmap::IndexMap<String, ResolvedStringOrProviderRef> = [
            ("yk1".to_string(), path("yk1.txt")),
            ("yk2".to_string(), path("yk2.txt")),
            (
                "fido".to_string(),
                ResolvedStringOrProviderRef::Provider(fido2.clone()),
            ),
        ]
        .into();
        let select = |default: Option<&str>, env_id: Option<&str>, inline: bool| {
            select_key_file_with(
                "age",
                Some("k.txt".into()),
                OptionProviderSecretRef::none(),
                &identities,
                default,
                env_id,
                inline,
            )
        };
        assert_eq!(
            select(Some("yk1"), None, false)
                .unwrap()
                .key_file
                .as_deref(),
            Some("yk1.txt")
        );
        // The environment name wins over default_identity.
        assert_eq!(
            select(Some("yk1"), Some("yk2"), false)
                .unwrap()
                .key_file
                .as_deref(),
            Some("yk2.txt")
        );
        assert_eq!(
            select(None, None, false).unwrap().key_file.as_deref(),
            Some("k.txt")
        );
        // An inline FNOX_AGE_KEY skips selection, even for an unknown name.
        assert_eq!(
            select(None, Some("nope"), true)
                .unwrap()
                .key_file
                .as_deref(),
            Some("k.txt")
        );
        // A provider-backed entry becomes the identity reference and drops key_file.
        let selected = select(Some("fido"), None, false).unwrap();
        assert_eq!(selected.key_file, None);
        assert_eq!(selected.identity.as_ref(), Some(&fido2));
        let err = select(None, Some("nope"), false).err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("'nope'"), "{msg}");
        assert!(msg.contains("(available: yk1, yk2, fido)"), "{msg}");
    }

    #[test]
    fn new_rejects_provider_backed_named_identity() {
        if env::fnox_age_key().is_some() || env::fnox_age_identity().is_some() {
            return;
        }
        let identities: indexmap::IndexMap<String, ResolvedStringOrProviderRef> = [(
            "fido".to_string(),
            ResolvedStringOrProviderRef::Provider(
                crate::providers::secret_ref::ProviderSecretRef {
                    provider: "fido2".to_string(),
                    value: "wrapped".to_string(),
                },
            ),
        )]
        .into();
        let err = AgeEncryptionProvider::new(
            vec![],
            None,
            OptionProviderSecretRef::none(),
            identities,
            Some("fido".to_string()),
        )
        .err()
        .expect("construction should fail without config");
        assert!(err.to_string().contains("needs the config"), "{err}");
    }

    fn passphrase_encrypt(plaintext: &str, armor: bool) -> Vec<u8> {
        let encryptor = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
            "hunter2".to_string(),
        ));
        let mut encrypted = vec![];
        let output = if armor {
            age::armor::ArmoredWriter::wrap_output(&mut encrypted, age::armor::Format::AsciiArmor)
                .unwrap()
        } else {
            age::armor::ArmoredWriter::wrap_output(&mut encrypted, age::armor::Format::Binary)
                .unwrap()
        };
        let mut writer = encryptor.wrap_output(output).unwrap();
        std::io::Write::write_all(&mut writer, plaintext.as_bytes()).unwrap();
        writer.finish().unwrap().finish().unwrap();
        encrypted
    }

    #[test]
    fn detects_and_decrypts_passphrase_encrypted_identity() {
        let identity = age::x25519::Identity::generate();
        let secret = identity.to_string();
        assert!(!is_age_encrypted(secret.expose_secret().as_bytes()));

        for armor in [false, true] {
            let encrypted = passphrase_encrypt(secret.expose_secret(), armor);
            assert_eq!(encrypted.starts_with(b"-----BEGIN AGE"), armor);
            assert!(is_age_encrypted(&encrypted));
            assert_eq!(
                decrypt_with_passphrase(&encrypted, "hunter2".to_string()).unwrap(),
                *secret.expose_secret()
            );
            assert!(decrypt_with_passphrase(&encrypted, "wrong".to_string()).is_err());
        }
    }

    fn test_provider() -> (AgeEncryptionProvider, tempfile::TempPath) {
        let identity = age::x25519::Identity::generate();
        let key_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key_file.path(), identity.to_string().expose_secret()).unwrap();
        let key_path = key_file.path().to_string_lossy().into_owned();
        let key_file = key_file.into_temp_path();

        (
            AgeEncryptionProvider::new(
                vec![identity.to_public().to_string()],
                Some(key_path),
                OptionProviderSecretRef::none(),
                Default::default(),
                None,
            )
            .unwrap(),
            key_file,
        )
    }

    #[test]
    fn inline_key_changes_preserve_identity_selection_and_cache_boundaries() {
        const CHILD: &str = "FNOX_TEST_INLINE_IDENTITY_CHILD";
        if env::var_os(CHILD).is_none() {
            // Environment changes stay in a separate, single-test process.
            let output = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "providers::age::tests::inline_key_changes_preserve_identity_selection_and_cache_boundaries",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env_remove("FNOX_AGE_KEY")
                .env_remove("FNOX_AGE_IDENTITY")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let first = age::x25519::Identity::generate();
                let second = age::x25519::Identity::generate();
                let directory = tempfile::tempdir().unwrap();
                let named = directory.path().join("named.txt");
                std::fs::write(&named, second.to_string().expose_secret()).unwrap();
                env::set_var("FNOX_AGE_KEY", first.to_string().expose_secret());
                let provider = AgeEncryptionProvider::new(
                    vec![second.to_public().to_string()],
                    Some(
                        directory
                            .path()
                            .join("missing.txt")
                            .to_string_lossy()
                            .into(),
                    ),
                    OptionProviderSecretRef::none(),
                    [(
                        "named".into(),
                        ResolvedStringOrProviderRef::String(named.to_string_lossy().into()),
                    )]
                    .into(),
                    Some("named".into()),
                )
                .unwrap();
                let named_ciphertext = provider.encrypt("named-value").await.unwrap();
                env::remove_var("FNOX_AGE_KEY");
                let named_result = provider.get_secret(&named_ciphertext).await;

                env::set_var("FNOX_AGE_KEY", first.to_string().expose_secret());
                let mut config = crate::config::Config::new();
                config
                    .provider_sources
                    .insert("age".into(), directory.path().join("fnox.toml"));
                let resolved = crate::providers::ResolvedProviderConfig::AgeEncryption {
                    recipients: vec![second.to_public().to_string()],
                    key_file: Some("missing.txt".into()),
                    identity: OptionProviderSecretRef::none(),
                    identities: [(
                        "named".into(),
                        ResolvedStringOrProviderRef::String("named.txt".into()),
                    )]
                    .into(),
                    default_identity: Some("named".into()),
                };
                let configured = crate::providers::get_provider_from_resolved_with_context(
                    &config,
                    &["default".into()],
                    "age",
                    &resolved,
                )
                .unwrap();
                env::remove_var("FNOX_AGE_KEY");
                assert_eq!(
                    configured.get_secret(&named_ciphertext).await.unwrap(),
                    "named-value"
                );
                env::set_var("FNOX_AGE_IDENTITY", "missing");
                assert!(configured.get_secret(&named_ciphertext).await.is_err());
                env::set_var("FNOX_AGE_KEY", second.to_string().expose_secret());
                assert_eq!(
                    configured.get_secret(&named_ciphertext).await.unwrap(),
                    "named-value"
                );
                env::remove_var("FNOX_AGE_IDENTITY");
                env::remove_var("FNOX_AGE_KEY");

                let provider = AgeEncryptionProvider::new(
                    vec![first.to_public().to_string()],
                    None,
                    OptionProviderSecretRef::none(),
                    Default::default(),
                    None,
                )
                .unwrap();
                let ciphertext = provider.encrypt("first-value").await.unwrap();
                let cached_result = with_decrypt_scope(async {
                    env::set_var("FNOX_AGE_KEY", first.to_string().expose_secret());
                    assert_eq!(
                        provider.get_secret(&ciphertext).await.unwrap(),
                        "first-value"
                    );
                    env::set_var("FNOX_AGE_KEY", second.to_string().expose_secret());
                    let replaced = provider.get_secret(&ciphertext).await;
                    env::remove_var("FNOX_AGE_KEY");
                    assert!(configured.get_secret(&ciphertext).await.is_err());
                    env::set_var("FNOX_AGE_KEY", first.to_string().expose_secret());
                    assert_eq!(
                        provider.get_secret(&ciphertext).await.unwrap(),
                        "first-value"
                    );
                    replaced
                })
                .await;
                env::remove_var("FNOX_AGE_KEY");
                assert!(
                    named_result.is_ok() && cached_result.is_err(),
                    "named identity restored: {}; unrelated replacement key rejected: {}",
                    named_result.is_ok(),
                    cached_result.is_err()
                );
                assert_eq!(named_result.unwrap(), "named-value");
            });
    }

    /// Regression test for the "incorrect HRP" failure on age plugin recipients
    /// (e.g. age-plugin-yubikey). A plugin recipient must now be recognized and
    /// dispatched to the plugin driver instead of being rejected by the native
    /// x25519 parser. This holds whether or not the plugin binary is installed:
    /// if it is, wrapping may succeed; if it isn't, the error is about the
    /// missing plugin binary -- never about an "incorrect HRP" / parse failure.
    #[tokio::test]
    async fn plugin_recipient_is_not_rejected_as_invalid_hrp() {
        let recipient =
            "age1yubikey1qwla8v7cu3mx6mp79asgrh5ad2h52flwln7c66ydcyy50lg5uh0gxh4kmaz".to_string();
        let provider = AgeEncryptionProvider::new(
            vec![recipient],
            None,
            OptionProviderSecretRef::none(),
            Default::default(),
            None,
        )
        .expect("provider construction should succeed");

        if let Err(err) = provider.encrypt("plaintext").await {
            let message = err.to_string();
            assert!(
                !message.contains("incorrect HRP"),
                "plugin recipient should not be rejected by the native parser: {message}"
            );
            assert!(
                !message.contains("Failed to parse recipient"),
                "plugin recipient should parse successfully: {message}"
            );
        }
    }

    #[tokio::test]
    async fn decrypt_scope_reuses_value_across_providers() {
        let (provider, key_file) = test_provider();
        let ciphertext = provider.encrypt("doppler-token").await.unwrap();

        with_decrypt_scope(async {
            assert_eq!(
                provider.get_secret(&ciphertext).await.unwrap(),
                "doppler-token"
            );
            key_file.close().unwrap();

            let (provider_without_key, _) = test_provider();
            assert_eq!(
                provider_without_key.get_secret(&ciphertext).await.unwrap(),
                "doppler-token"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn decrypts_are_not_reused_outside_a_scope() {
        let (provider, key_file) = test_provider();
        let ciphertext = provider.encrypt("doppler-token").await.unwrap();

        with_decrypt_scope(provider.get_secret(&ciphertext))
            .await
            .unwrap();
        key_file.close().unwrap();

        let (provider_without_key, _) = test_provider();
        assert!(provider_without_key.get_secret(&ciphertext).await.is_err());
        assert!(
            with_decrypt_scope(provider_without_key.get_secret(&ciphertext))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn overlapping_decrypts_in_a_scope_run_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        let decrypt = || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Ok("shared".to_string())
        };

        let (first, second) = with_decrypt_scope(async {
            tokio::join!(
                decrypt_once("ciphertext", None, decrypt),
                decrypt_once("ciphertext", None, decrypt)
            )
        })
        .await;

        assert_eq!(first.unwrap(), "shared");
        assert_eq!(second.unwrap(), "shared");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_decrypt_in_a_scope_can_be_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        let decrypt = || async {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(FnoxError::AgeDecryptionFailed {
                    details: "wrong PIN".to_string(),
                })
            } else {
                Ok("retry".to_string())
            }
        };

        let (first, second) = with_decrypt_scope(async {
            let first = decrypt_once("ciphertext", None, decrypt).await;
            let second = decrypt_once("ciphertext", None, decrypt).await;
            (first, second)
        })
        .await;

        assert!(first.is_err());
        assert_eq!(second.unwrap(), "retry");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn batch_encryption_wraps_one_shared_key_and_round_trips() {
        let (provider, _key_file) = test_provider();
        let plaintext = vec![
            ("FIRST".to_string(), "one".to_string()),
            ("SECOND".to_string(), "two".to_string()),
        ];

        let encrypted = provider.encrypt_secrets_batch(&plaintext).await;
        let first = encrypted["FIRST"].as_ref().unwrap();
        let second = encrypted["SECOND"].as_ref().unwrap();
        let (first_wrapped_key, _) = AgeEncryptionProvider::parse_batch_value(first).unwrap();
        let (second_wrapped_key, _) = AgeEncryptionProvider::parse_batch_value(second).unwrap();
        assert_eq!(first_wrapped_key, second_wrapped_key);

        let ciphertexts = encrypted
            .into_iter()
            .map(|(key, value)| (key, value.unwrap()))
            .collect::<Vec<_>>();
        let decrypted = provider.get_secrets_batch(&ciphertexts).await;

        assert_eq!(decrypted["FIRST"].as_ref().unwrap(), "one");
        assert_eq!(decrypted["SECOND"].as_ref().unwrap(), "two");
    }
}
