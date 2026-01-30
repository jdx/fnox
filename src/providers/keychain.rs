use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use keyring::Entry;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

pub struct KeychainProvider {
    service: String,
    prefix: Option<String>,
}

impl KeychainProvider {
    pub fn new(service: String, prefix: Option<String>) -> Self {
        Self { service, prefix }
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
        let full_key = self.build_key_name(key);
        Entry::new(&self.service, &full_key).map_err(|e| FnoxError::ProviderApiError {
            provider: "Keychain".to_string(),
            details: format!(
                "Failed to create entry for service '{}', key '{}': {}",
                self.service, full_key, e
            ),
            hint: "Check that the keychain is accessible".to_string(),
            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
        })
    }

    /// Store a secret in the OS keychain
    pub async fn put_secret(&self, key: &str, value: &str) -> Result<()> {
        let entry = self.create_entry(key)?;
        let full_key = self.build_key_name(key);

        tracing::debug!(
            "Storing secret '{}' in OS keychain (service: '{}', key: '{}')",
            full_key,
            self.service,
            full_key
        );

        entry
            .set_password(value)
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Keychain".to_string(),
                details: format!(
                    "Failed to store secret '{}' (service: '{}'): {}",
                    full_key, self.service, e
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

        tracing::debug!(
            "Getting secret '{}' from OS keychain (service: '{}')",
            full_key,
            self.service
        );

        entry.get_password().map_err(|e| {
            let err_str = e.to_string();
            // keyring errors can be: NoEntry, NoStorageAccess, PlatformFailure, etc.
            // Linux Secret Service returns "No matching entry found in secure storage"
            if err_str.contains("No entry")
                || err_str.contains("No matching entry")
                || err_str.contains("not found")
                || err_str.contains("ItemNotFound")
            {
                FnoxError::ProviderSecretNotFound {
                    provider: "Keychain".to_string(),
                    secret: full_key.clone(),
                    hint: format!(
                        "Check that the secret exists in the keychain (service: '{}')",
                        self.service
                    ),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                }
            } else if err_str.contains("access")
                || err_str.contains("permission")
                || err_str.contains("locked")
            {
                FnoxError::ProviderAuthFailed {
                    provider: "Keychain".to_string(),
                    details: err_str,
                    hint: "Check that the keychain is unlocked and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "Keychain".to_string(),
                    details: err_str,
                    hint: format!(
                        "Failed to get secret from keychain (service: '{}')",
                        self.service
                    ),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                }
            }
        })
    }

    async fn test_connection(&self) -> Result<()> {
        // Try to create an entry with a test key to verify keychain access
        let test_key = "__fnox_test__";
        let entry = self.create_entry(test_key)?;

        // Try to set a test value to verify we have keychain access
        entry
            .set_password("test")
            .map_err(|e| FnoxError::ProviderAuthFailed {
                provider: "Keychain".to_string(),
                details: format!(
                    "Failed to access keychain (service: '{}'): {}",
                    self.service, e
                ),
                hint: "Check that you have permission to access the OS keychain".to_string(),
                url: "https://fnox.jdx.dev/providers/keychain".to_string(),
            })?;

        // Try to read it back to verify it worked
        entry
            .get_password()
            .map_err(|e| FnoxError::ProviderAuthFailed {
                provider: "Keychain".to_string(),
                details: format!(
                    "Failed to verify keychain access (service: '{}'): {}",
                    self.service, e
                ),
                hint: "Check that you have permission to access the OS keychain".to_string(),
                url: "https://fnox.jdx.dev/providers/keychain".to_string(),
            })?;

        // Clean up the test entry (delete_credential in keyring v3)
        let _ = entry.delete_credential();

        Ok(())
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
        let provider = KeychainProvider::new("fnox-unit-test".to_string(), None);

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
