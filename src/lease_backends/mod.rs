use crate::error::Result;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub mod aws_sts;

/// A credential lease with metadata for tracking and revocation
#[derive(Debug, Clone)]
pub struct Lease {
    /// The credentials (provider-specific format, e.g. AWS_ACCESS_KEY_ID -> value)
    pub credentials: HashMap<String, String>,
    /// When this lease expires (None = no automatic expiry)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Lease ID for tracking/revocation
    pub lease_id: String,
}

/// Lease backend capability for vending short-lived credentials (experimental)
#[async_trait]
pub trait LeaseBackend: Send + Sync {
    /// Create a short-lived credential from the master credential
    async fn create_lease(&self, value: &str, duration: Duration, label: &str) -> Result<Lease>;

    /// Revoke a previously issued lease (for cleanup)
    async fn revoke_lease(&self, _lease_id: &str) -> Result<()> {
        // Default: no-op (for backends with native TTL)
        Ok(())
    }

    /// Maximum allowed lease duration
    fn max_lease_duration(&self) -> Duration;

}

/// Configuration for a lease backend (manually defined, no codegen)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum LeaseBackendConfig {
    /// AWS STS AssumeRole
    AwsSts {
        region: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        role_arn: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
    },
}

impl LeaseBackendConfig {
    /// Create a lease backend instance from this configuration
    pub fn create_backend(&self) -> Result<Box<dyn LeaseBackend>> {
        match self {
            LeaseBackendConfig::AwsSts {
                region,
                profile,
                role_arn,
                endpoint,
            } => Ok(Box::new(aws_sts::AwsStsBackend::new(
                region.clone(),
                profile.clone(),
                role_arn.clone(),
                endpoint.clone(),
            ))),
        }
    }
}
