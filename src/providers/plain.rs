use crate::error::Result;
use crate::providers::{WizardCategory, WizardInfo};
use async_trait::async_trait;

pub const WIZARD_INFO: WizardInfo = WizardInfo {
    provider_type: "plain",
    display_name: "Plain text",
    description: "No encryption - stores values directly in config (not recommended for sensitive data)",
    category: WizardCategory::Local,
    setup_instructions: "\
Plain provider stores secrets unencrypted in your config file.
Only use this for non-sensitive values or development.",
    default_name: "plain",
    fields: &[],
};

/// Plain provider that stores and returns values as-is without encryption.
///
/// This provider is useful for:
/// - Development and testing
/// - Non-sensitive configuration values
/// - Simple string storage
///
/// WARNING: Values are stored in plain text in the configuration file.
/// Do not use this provider for sensitive secrets in production.
#[derive(Default)]
pub struct PlainProvider;

impl PlainProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl crate::providers::Provider for PlainProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        // Plain provider stores values as-is (no actual encryption)
        // We return Encryption to indicate it handles the value directly
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        // Simply return the value as-is
        Ok(value.to_string())
    }

    async fn encrypt(&self, value: &str) -> Result<String> {
        // Plain provider stores values as-is without encryption
        Ok(value.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        // Plain provider is always available
        Ok(())
    }
}
