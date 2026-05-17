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
}

impl KeychainProvider {
    pub fn new(service: String, prefix: Option<String>) -> Result<Self> {
        Ok(Self { service, prefix })
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
        Entry::new(&self.service, &full_key).map_err(|e| match e {
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

    /// Store a secret in the OS keychain.
    ///
    /// The underlying `keyring-core` call is synchronous and on macOS may
    /// present a Security framework dialog that blocks until the user
    /// responds. We run it on a blocking thread pool so the tokio runtime
    /// keeps making progress (and so concurrent calls don't pin every worker
    /// thread).
    pub async fn put_secret(&self, key: &str, value: &str) -> Result<()> {
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

/// Run a blocking keyring call on tokio's blocking thread pool.
///
/// The OS keychain APIs are synchronous and may present a system dialog that
/// blocks until the user responds. Calling them directly on a tokio worker
/// thread pins that thread — concurrent calls can deadlock the runtime.
async fn spawn_keychain_blocking<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| FnoxError::ProviderApiError {
            provider: "Keychain".to_string(),
            details: format!("Keychain task failed to complete: {e}"),
            hint: "This is a bug; please report it".to_string(),
            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
        })
}

fn platform_backend_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "No OS keyring backend is available. Start a Secret Service provider \
         (e.g. gnome-keyring or KeePassXC) and make sure DBUS_SESSION_BUS_ADDRESS \
         is set."
    }
    #[cfg(target_os = "macos")]
    {
        "Failed to initialize the macOS Keychain backend."
    }
    #[cfg(target_os = "windows")]
    {
        "Failed to initialize the Windows Credential Manager backend."
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "The keychain provider is not supported on this platform."
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;

    #[tokio::test]
    async fn test_keychain_set_and_get() {
        let provider = KeychainProvider::new("fnox-unit-test".to_string(), None).unwrap();

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
}
