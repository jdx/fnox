use super::support::{platform_backend_hint, spawn_keychain_blocking};
#[cfg(target_os = "macos")]
use super::{
    support::{invoking_command_cstring, touch_id_error_hint},
    touch_id::{delete, get, set},
};
#[cfg(target_os = "macos")]
use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use keyring_core::Entry;
use std::collections::HashMap;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

pub struct KeychainProvider {
    service: String,
    prefix: Option<String>,
    touch_id: bool,
}

impl KeychainProvider {
    pub fn new(service: String, prefix: Option<String>, touch_id: bool) -> Result<Self> {
        if touch_id && !cfg!(target_os = "macos") {
            return Err(FnoxError::Provider(
                "The keychain provider's touch_id option is supported only on macOS".to_string(),
            ));
        }
        Ok(Self {
            service,
            prefix,
            touch_id,
        })
    }

    /// Build the full key name with optional prefix
    fn build_key_name(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}{}", prefix, key),
            None => key.to_string(),
        }
    }

    /// Create a keyring entry
    fn create_entry(&self, key: &str) -> Result<Entry> {
        crate::keyring_store::init();
        let full_key = self.build_key_name(key);
        let service = self.effective_service();
        Entry::new(&service, &full_key).map_err(|e| match e {
            // `Entry::new` itself fails with `NoDefaultStore` when the platform
            // backend couldn't be registered (e.g. headless Linux without
            // Secret Service). Surface a backend-specific hint here, since the
            // call never reaches `get_password`/`set_password`.
            keyring_core::Error::NoDefaultStore => FnoxError::ProviderAuthFailed {
                provider: "Keychain".to_string(),
                details: e.to_string(),
                hint: platform_backend_hint().to_string(),
                url: "https://fnox.jdx.dev/providers/keychain".to_string(),
            },
            _ => FnoxError::ProviderApiError {
                provider: "Keychain".to_string(),
                details: format!(
                    "Failed to create entry for service '{}', key '{}': {}",
                    self.service, full_key, e
                ),
                hint: "Check that the keychain is accessible".to_string(),
                url: "https://fnox.jdx.dev/providers/keychain".to_string(),
            },
        })
    }

    fn effective_service(&self) -> String {
        if self.touch_id {
            format!("{}.touch-id", self.service)
        } else {
            self.service.clone()
        }
    }

    /// Store a secret in the OS keychain.
    ///
    /// The underlying `keyring-core` call is synchronous and on macOS may
    /// present a Security framework dialog that blocks until the user
    /// responds. We run it on a blocking thread pool so the tokio runtime
    /// keeps making progress (and so concurrent calls don't pin every worker
    /// thread).
    pub async fn put_secret(&self, key: &str, value: &str) -> Result<()> {
        if self.touch_id {
            #[cfg(target_os = "macos")]
            {
                let service = self.effective_service();
                let account = self.build_key_name(key);
                let reason = format!("Update protected Fnox Keychain secret '{account}'");
                let service_c = std::ffi::CString::new(service.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Service names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let account_c = std::ffi::CString::new(account.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let reason_c =
                    std::ffi::CString::new(reason).map_err(|e| FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key name cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    })?;
                let value_bytes = value.as_bytes().to_vec();
                let result = spawn_keychain_blocking(move || {
                    set(&service_c, &account_c, &value_bytes, &reason_c)
                })
                .await?;
                return result.map_err(|(status, details)| FnoxError::ProviderApiError {
                    provider: "Keychain".to_string(),
                    details: format!("Touch ID Keychain write failed (status {status}): {details}"),
                    hint: touch_id_error_hint(status).to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                });
            }
        }
        let entry = self.create_entry(key)?;
        let full_key = self.build_key_name(key);
        let service = self.service.clone();

        tracing::debug!(
            "Storing secret '{}' in OS keychain (service: '{}', key: '{}')",
            full_key,
            self.service,
            full_key
        );

        let value = value.to_string();
        let set_full_key = full_key.clone();
        let set_service = service.clone();
        spawn_keychain_blocking(move || entry.set_password(&value))
            .await?
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Keychain".to_string(),
                details: format!(
                    "Failed to store secret '{}' (service: '{}'): {}",
                    set_full_key, set_service, e
                ),
                hint: "Check that the keychain is accessible and writable".to_string(),
                url: "https://fnox.jdx.dev/providers/keychain".to_string(),
            })?;

        tracing::debug!(
            "Successfully stored secret '{}' in OS keychain (service: '{}')",
            full_key,
            self.service
        );
        Ok(())
    }
}

#[async_trait]
impl crate::providers::Provider for KeychainProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        if self.touch_id {
            #[cfg(target_os = "macos")]
            {
                let service = self.effective_service();
                let account = self.build_key_name(value);
                let reason = format!("access the protected Fnox secret '{account}'");
                let service_c = std::ffi::CString::new(service.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Service names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let account_c = std::ffi::CString::new(account.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let reason_c =
                    std::ffi::CString::new(reason).map_err(|e| FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key name cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    })?;
                let executable_c = std::ffi::CString::new(
                    env::current_exe()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "fnox".to_string()),
                )
                .expect("executable path cannot contain NUL bytes");
                let project_c = std::ffi::CString::new(
                    env::current_dir()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
                .expect("current directory cannot contain NUL bytes");
                let command_c = invoking_command_cstring();
                let result = spawn_keychain_blocking(move || {
                    get(
                        &service_c,
                        &account_c,
                        &reason_c,
                        &executable_c,
                        &project_c,
                        &command_c,
                    )
                })
                .await?;
                return result.map_err(|(status, details)| {
                    if status == -25300 {
                        FnoxError::ProviderSecretNotFound {
                            provider: "Keychain (Touch ID)".to_string(),
                            secret: account,
                            hint: format!("Check that the secret exists in the protected Keychain service '{service}'"),
                            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                        }
                    } else {
                        FnoxError::ProviderAuthFailed {
                            provider: "Keychain (Touch ID)".to_string(),
                            details: format!("Touch ID Keychain read failed (status {status}): {details}"),
                            hint: touch_id_error_hint(status).to_string(),
                            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                        }
                    }
                });
            }
        }
        let entry = self.create_entry(value)?;
        let full_key = self.build_key_name(value);
        let service = self.service.clone();

        tracing::debug!(
            "Getting secret '{}' from OS keychain (service: '{}')",
            full_key,
            service
        );

        spawn_keychain_blocking(move || entry.get_password())
            .await?
            .map_err(|e| match e {
                keyring_core::Error::NoEntry => FnoxError::ProviderSecretNotFound {
                    provider: "Keychain".to_string(),
                    secret: full_key.clone(),
                    hint: format!(
                        "Check that the secret exists in the keychain (service: '{}')",
                        service
                    ),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                },
                keyring_core::Error::NoStorageAccess(_) => FnoxError::ProviderAuthFailed {
                    provider: "Keychain".to_string(),
                    details: e.to_string(),
                    hint: "Check that the keychain is unlocked and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                },
                _ => FnoxError::ProviderApiError {
                    provider: "Keychain".to_string(),
                    details: e.to_string(),
                    hint: format!(
                        "Failed to get secret from keychain (service: '{}')",
                        service
                    ),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                },
            })
    }

    /// Override the default parallel `get_secrets_batch` to fetch keychain
    /// entries sequentially.
    ///
    /// The OS keychain API is synchronous and can pop a confirmation dialog
    /// per access. Running them concurrently would surface several
    /// overlapping dialogs and — once the number of secrets reaches the
    /// tokio worker-thread count — would also deadlock the runtime even with
    /// `spawn_blocking`, since the runtime still needs at least one free
    /// thread to drive completions.
    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let mut results = HashMap::with_capacity(secrets.len());
        for (key, value) in secrets {
            results.insert(key.clone(), self.get_secret(value).await);
        }
        results
    }

    async fn test_connection(&self) -> Result<()> {
        if self.touch_id {
            #[cfg(target_os = "macos")]
            {
                if env::is_non_interactive() {
                    return Err(FnoxError::ProviderAuthFailed {
                        provider: "Keychain (Touch ID)".to_string(),
                        details: "Touch ID connection tests require an interactive terminal"
                            .to_string(),
                        hint: "Run the command in an interactive terminal".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    });
                }
                let test_account = format!("__fnox_touch_id_test_{:032x}", rand::random::<u128>());
                let service = format!("{}.test", self.effective_service());
                let service_c = std::ffi::CString::new(service.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Service names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let account_c = std::ffi::CString::new(test_account).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let reason_c =
                    std::ffi::CString::new("validate Touch ID protected Keychain access")
                        .expect("static Touch ID reason contains no NUL bytes");
                let write_result = spawn_keychain_blocking({
                    let service_c = service_c.clone();
                    let account_c = account_c.clone();
                    let reason_c = reason_c.clone();
                    move || set(&service_c, &account_c, b"fnox-touch-id-test", &reason_c)
                })
                .await?;
                write_result.map_err(|(status, details)| FnoxError::ProviderAuthFailed {
                    provider: "Keychain (Touch ID)".to_string(),
                    details: format!(
                        "Protected Keychain write failed (status {status}): {details}"
                    ),
                    hint: touch_id_error_hint(status).to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                })?;

                let executable_c = std::ffi::CString::new(
                    env::current_exe()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "fnox".to_string()),
                )
                .expect("executable path cannot contain NUL bytes");
                let project_c = std::ffi::CString::new(
                    env::current_dir()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
                .expect("project path cannot contain NUL bytes");
                let command_c = invoking_command_cstring();
                let (read_result, cleanup_result) = spawn_keychain_blocking({
                    let service_c = service_c.clone();
                    let account_c = account_c.clone();
                    let reason_c = reason_c.clone();
                    move || {
                        let read = get(
                            &service_c,
                            &account_c,
                            &reason_c,
                            &executable_c,
                            &project_c,
                            &command_c,
                        );
                        let cleanup = delete(&service_c, &account_c);
                        (read, cleanup)
                    }
                })
                .await?;
                read_result.map_err(|(status, details)| FnoxError::ProviderAuthFailed {
                    provider: "Keychain (Touch ID)".to_string(),
                    details: format!("Protected Keychain read failed (status {status}): {details}"),
                    hint: "Approve the Fnox Touch ID request and retry".to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                })?;
                cleanup_result.map_err(|(status, details)| FnoxError::ProviderApiError {
                    provider: "Keychain (Touch ID)".to_string(),
                    details: format!("Unable to remove the temporary validation entry (status {status}): {details}"),
                    hint: "Remove the temporary Fnox Touch ID validation item from Keychain Access"
                        .to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                })?;
                return Ok(());
            }
        }
        // Try to create an entry with a test key to verify keychain access
        let test_key = "__fnox_test__";
        let entry = self.create_entry(test_key)?;
        let service = self.service.clone();

        // Run all three blocking operations on a single background thread to
        // avoid hopping through the runtime three times.
        spawn_keychain_blocking(move || {
            entry.set_password("test")?;
            entry.get_password()?;
            let _ = entry.delete_credential();
            Ok(())
        })
        .await?
        .map_err(|e: keyring_core::Error| FnoxError::ProviderAuthFailed {
            provider: "Keychain".to_string(),
            details: format!("Failed to access keychain (service: '{service}'): {e}"),
            hint: "Check that you have permission to access the OS keychain".to_string(),
            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
        })
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        self.put_secret(key, value).await?;
        // Return the key name to store in config
        Ok(key.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;

    #[tokio::test]
    async fn test_keychain_set_and_get() {
        let provider = KeychainProvider::new("fnox-unit-test".to_string(), None, false).unwrap();

        if let Err(err) = provider.test_connection().await {
            if is_keychain_unavailable(&err) {
                eprintln!("skipping keychain test: {err}");
                return;
            }
            panic!("Failed to connect to keychain: {err:?}");
        }

        // Set a secret
        let result = provider.put_secret("test_key", "test_value").await;
        assert!(result.is_ok(), "Failed to set secret: {:?}", result.err());

        // Get it back
        let result = provider.get_secret("test_key").await;
        assert!(result.is_ok(), "Failed to get secret: {:?}", result.err());
        assert_eq!(result.unwrap(), "test_value");

        // Clean up
        let entry = provider.create_entry("test_key").unwrap();
        let _ = entry.delete_credential();
    }

    fn is_keychain_unavailable(err: &FnoxError) -> bool {
        matches!(err, FnoxError::ProviderAuthFailed { .. })
    }
}
