use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use keyring::Entry;

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
        Entry::new(&self.service, &full_key).map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to create keyring entry for service '{}', key '{}': {}",
                self.service, full_key, e
            ))
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

        entry.set_password(value).map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to store secret '{}' in keychain (service: '{}'): {}",
                full_key, self.service, e
            ))
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
            FnoxError::Provider(format!(
                "Failed to retrieve secret '{}' from keychain: {}",
                full_key, e
            ))
        })
    }

    async fn test_connection(&self) -> Result<()> {
        // Try to create an entry with a test key to verify keychain access
        let test_key = "__fnox_test__";
        let entry = self.create_entry(test_key)?;

        // Try to set a test value to verify we have keychain access
        entry.set_password("test").map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to access OS keychain (service: '{}'): {}",
                self.service, e
            ))
        })?;

        // Try to read it back to verify it worked
        entry.get_password().map_err(|e| {
            FnoxError::Provider(format!(
                "Failed to verify OS keychain access (service: '{}'): {}",
                self.service, e
            ))
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
