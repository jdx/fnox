use crate::error::Result;
use async_trait::async_trait;
use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod aws_sts;
pub mod azure_token;
pub mod cloudflare;
pub mod command;
pub mod gcp_iam;
pub mod vault;

/// A credential lease with metadata for tracking and revocation
#[derive(Debug, Clone)]
pub struct Lease {
    /// The credentials (provider-specific format, e.g. AWS_ACCESS_KEY_ID -> value)
    pub credentials: IndexMap<String, String>,
    /// When this lease expires (None = no automatic expiry)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Lease ID for tracking/revocation
    pub lease_id: String,
}

/// Lease backend capability for vending short-lived credentials
#[async_trait]
pub trait LeaseBackend: Send + Sync {
    /// Create a short-lived credential
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease>;

    /// Revoke a previously issued lease (for cleanup)
    async fn revoke_lease(&self, _lease_id: &str) -> Result<()> {
        // Default: no-op (for backends with native TTL)
        Ok(())
    }

    /// Maximum allowed lease duration
    fn max_lease_duration(&self) -> Duration;
}

fn default_gcp_scopes() -> Vec<String> {
    vec!["https://www.googleapis.com/auth/cloud-platform".to_string()]
}

fn default_command_timeout() -> String {
    "30s".to_string()
}

fn default_gcp_env_var() -> String {
    "CLOUDSDK_AUTH_ACCESS_TOKEN".to_string()
}

fn default_vault_method() -> String {
    "get".to_string()
}

fn default_azure_env_var() -> String {
    "AZURE_ACCESS_TOKEN".to_string()
}

fn default_cloudflare_env_var() -> String {
    "CLOUDFLARE_API_TOKEN".to_string()
}

/// Generate a unique lease ID with a prefix.
/// Appends a random suffix to avoid collisions between concurrent invocations.
pub fn generate_lease_id(prefix: &str) -> String {
    use rand::Rng;
    let suffix: u64 = rand::thread_rng().r#gen();
    format!("{prefix}-{suffix:016x}")
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
        role_arn: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// GCP Service Account Impersonation
    GcpIam {
        service_account_email: String,
        #[serde(default = "default_gcp_scopes")]
        scopes: Vec<String>,
        #[serde(default = "default_gcp_env_var")]
        env_var: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// HashiCorp Vault Dynamic Secrets
    Vault {
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        secret_path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
        env_map: IndexMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
        /// HTTP method: "get" (default) or "post" (required for pki/issue and some engines)
        #[serde(default = "default_vault_method")]
        method: String,
    },
    /// Azure Token Acquisition
    AzureToken {
        scope: String,
        #[serde(default = "default_azure_env_var")]
        env_var: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// Cloudflare API Token
    Cloudflare {
        #[serde(skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policies: Option<Vec<cloudflare::CloudflarePolicy>>,
        #[serde(default = "default_cloudflare_env_var")]
        env_var: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// Generic Command Backend
    Command {
        create_command: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        revoke_command: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
        /// Timeout for command execution (e.g., "30s", "2m"; default: "30s")
        #[serde(default = "default_command_timeout")]
        timeout: String,
    },
}

impl LeaseBackendConfig {
    /// Check if the prerequisites for this backend are available.
    /// Returns a human-readable message describing what's missing, or None if ready.
    pub fn check_prerequisites(&self) -> Option<String> {
        match self {
            LeaseBackendConfig::AwsSts { profile, .. } => {
                // AWS SDK supports many auth methods; check the most common ones
                let has_env = (std::env::var("AWS_ACCESS_KEY_ID").is_ok()
                    && std::env::var("AWS_SECRET_ACCESS_KEY").is_ok())
                    || std::env::var("AWS_PROFILE").is_ok();
                let has_profile = profile.is_some();
                let has_sso = std::env::var("AWS_SSO_SESSION").is_ok();
                let has_creds_file = dirs::home_dir()
                    .map(|h| h.join(".aws/credentials").exists() || h.join(".aws/config").exists())
                    .unwrap_or(false);
                if has_env || has_profile || has_sso || has_creds_file {
                    None
                } else {
                    Some("AWS credentials not found. Run 'aws sso login' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.".to_string())
                }
            }
            LeaseBackendConfig::GcpIam { .. } => {
                let has_env = std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok()
                    || std::env::var("GCP_SERVICE_ACCOUNT_KEY").is_ok();
                let has_adc = dirs::config_dir()
                    .map(|c| {
                        c.join("gcloud/application_default_credentials.json")
                            .exists()
                    })
                    .unwrap_or(false);
                if has_env || has_adc {
                    None
                } else {
                    Some("GCP credentials not found. Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS.".to_string())
                }
            }
            LeaseBackendConfig::Vault { address, token, .. } => {
                let has_addr = address.is_some()
                    || std::env::var("VAULT_ADDR").is_ok()
                    || std::env::var("FNOX_VAULT_ADDR").is_ok();
                let has_token = token.is_some()
                    || std::env::var("VAULT_TOKEN").is_ok()
                    || std::env::var("FNOX_VAULT_TOKEN").is_ok();
                match (has_addr, has_token) {
                    (false, false) => Some(
                        "Vault address and token not found. Set VAULT_ADDR and VAULT_TOKEN."
                            .to_string(),
                    ),
                    (false, true) => Some("Vault address not found. Set VAULT_ADDR.".to_string()),
                    (true, false) => Some("Vault token not found. Set VAULT_TOKEN.".to_string()),
                    (true, true) => None,
                }
            }
            LeaseBackendConfig::AzureToken { .. } => {
                let has_sp = std::env::var("AZURE_CLIENT_ID").is_ok()
                    && std::env::var("AZURE_CLIENT_SECRET").is_ok()
                    && std::env::var("AZURE_TENANT_ID").is_ok();
                if has_sp {
                    return None;
                }
                let has_az = which::which("az").is_ok();
                if has_az {
                    // az CLI is installed but we can't verify login state without
                    // running a subprocess; hint the user to check if auth fails later
                    None
                } else {
                    Some("Azure credentials not found. Run 'az login' or set AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID.".to_string())
                }
            }
            LeaseBackendConfig::Cloudflare { .. } => {
                let has_token = std::env::var("CLOUDFLARE_API_TOKEN").is_ok()
                    || std::env::var("CF_API_TOKEN").is_ok();
                if has_token {
                    None
                } else {
                    Some("Cloudflare API token not found. Set CLOUDFLARE_API_TOKEN with a token that has 'API Tokens: Edit' permission.".to_string())
                }
            }
            LeaseBackendConfig::Command { .. } => {
                // Can't easily validate command availability without running it
                None
            }
        }
    }

    /// Returns a list of (env_var_name, description) pairs for env vars the user
    /// can set to satisfy prerequisites. Used by `fnox lease create` to prompt
    /// interactively for missing credentials.
    pub fn required_env_vars(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            LeaseBackendConfig::AwsSts { .. } => vec![
                ("AWS_ACCESS_KEY_ID", "AWS access key"),
                ("AWS_SECRET_ACCESS_KEY", "AWS secret key"),
                ("AWS_SESSION_TOKEN", "AWS session token (optional)"),
            ],
            LeaseBackendConfig::GcpIam { .. } => vec![(
                "GOOGLE_APPLICATION_CREDENTIALS",
                "path to service account JSON key file",
            )],
            LeaseBackendConfig::Vault { address, token, .. } => {
                let mut vars = vec![];
                if address.is_none() {
                    vars.push((
                        "VAULT_ADDR",
                        "Vault server address (e.g., http://localhost:8200)",
                    ));
                }
                if token.is_none() {
                    vars.push(("VAULT_TOKEN", "Vault authentication token"));
                }
                vars
            }
            LeaseBackendConfig::AzureToken { .. } => vec![
                ("AZURE_CLIENT_ID", "Azure application (client) ID"),
                ("AZURE_CLIENT_SECRET", "Azure client secret"),
                ("AZURE_TENANT_ID", "Azure tenant (directory) ID"),
            ],
            LeaseBackendConfig::Cloudflare { .. } => vec![(
                "CLOUDFLARE_API_TOKEN",
                "Cloudflare API token with 'API Tokens: Edit' permission (or set CF_API_TOKEN)",
            )],
            LeaseBackendConfig::Command { .. } => vec![],
        }
    }

    /// Create a lease backend instance from this configuration
    pub fn create_backend(&self) -> Result<Box<dyn LeaseBackend>> {
        match self {
            LeaseBackendConfig::AwsSts {
                region,
                profile,
                role_arn,
                endpoint,
                ..
            } => Ok(Box::new(aws_sts::AwsStsBackend::new(
                region.clone(),
                profile.clone(),
                role_arn.clone(),
                endpoint.clone(),
            ))),
            LeaseBackendConfig::GcpIam {
                service_account_email,
                scopes,
                env_var,
                ..
            } => Ok(Box::new(gcp_iam::GcpIamBackend::new(
                service_account_email.clone(),
                scopes.clone(),
                env_var.clone(),
            ))),
            LeaseBackendConfig::Vault {
                address,
                token,
                secret_path,
                namespace,
                env_map,
                method,
                ..
            } => Ok(Box::new(vault::VaultBackend::new(
                address.clone(),
                token.clone(),
                secret_path.clone(),
                namespace.clone(),
                env_map.clone(),
                method.clone(),
            )?)),
            LeaseBackendConfig::AzureToken { scope, env_var, .. } => Ok(Box::new(
                azure_token::AzureTokenBackend::new(scope.clone(), env_var.clone()),
            )),
            LeaseBackendConfig::Cloudflare {
                account_id,
                policies,
                env_var,
                ..
            } => Ok(Box::new(cloudflare::CloudflareBackend::new(
                account_id.clone(),
                policies.clone(),
                env_var.clone(),
            ))),
            LeaseBackendConfig::Command {
                create_command,
                revoke_command,
                timeout,
                ..
            } => {
                let timeout = crate::lease::parse_duration(timeout)?;
                Ok(Box::new(command::CommandBackend::new(
                    create_command.clone(),
                    revoke_command.clone(),
                    timeout,
                )))
            }
        }
    }

    /// Compute a stable hash of security-relevant backend configuration.
    /// Used to detect config changes and invalidate cached lease credentials.
    /// Excludes `duration` and `timeout` since changing these doesn't invalidate
    /// existing cached credentials (e.g., switching from "1h" to "2h" shouldn't
    /// force a fresh lease when cached credentials are still valid).
    pub fn config_hash(&self) -> String {
        let mut serialized =
            serde_json::to_value(self).expect("LeaseBackendConfig serialization should never fail");
        // Strip non-security-relevant fields that shouldn't invalidate cache.
        // With #[serde(tag = "type")] the JSON is flat: {"type":"aws-sts","duration":"1h",...}
        if let Some(obj) = serialized.as_object_mut() {
            obj.remove("duration");
            obj.remove("timeout");
        }
        let json = serde_json::to_string(&serialized)
            .expect("LeaseBackendConfig serialization should never fail");
        let hash = blake3::hash(json.as_bytes());
        hash.to_hex()[..16].to_string()
    }

    /// Get the configured duration string, if any
    pub fn duration(&self) -> Option<&str> {
        match self {
            LeaseBackendConfig::AwsSts { duration, .. }
            | LeaseBackendConfig::GcpIam { duration, .. }
            | LeaseBackendConfig::Vault { duration, .. }
            | LeaseBackendConfig::AzureToken { duration, .. }
            | LeaseBackendConfig::Cloudflare { duration, .. }
            | LeaseBackendConfig::Command { duration, .. } => duration.as_deref(),
        }
    }
}
