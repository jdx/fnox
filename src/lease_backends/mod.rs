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
pub mod github_app;
pub mod pulumi_esc;
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

    /// Revoke a previously issued lease (for cleanup).
    /// `credentials` contains the cached credential values (decrypted) when
    /// available — backends that need a credential value for revocation (e.g.
    /// GitHub App, which must authenticate DELETE with the token itself) can
    /// look it up here instead of storing secrets in `lease_id`.
    async fn revoke_lease(
        &self,
        _lease_id: &str,
        _credentials: Option<&IndexMap<String, String>>,
    ) -> Result<()> {
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

fn default_github_env_var() -> String {
    "GITHUB_TOKEN".to_string()
}

/// Generate a unique lease ID with a prefix.
/// Appends a random suffix to avoid collisions between concurrent invocations.
pub fn generate_lease_id(prefix: &str) -> String {
    let suffix: u64 = rand::random();
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
        /// Token type: "user" (default) or "account"
        #[serde(default)]
        token_type: cloudflare::CloudflareTokenType,
        #[serde(skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policies: Option<Vec<cloudflare::CloudflarePolicy>>,
        #[serde(default = "default_cloudflare_env_var")]
        env_var: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// GitHub App Installation Token
    GithubApp {
        app_id: String,
        installation_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        private_key_file: Option<String>,
        #[serde(default = "default_github_env_var")]
        env_var: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        permissions: Option<IndexMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        repositories: Option<Vec<String>>,
        /// GitHub API base URL (default: https://api.github.com)
        #[serde(skip_serializing_if = "Option::is_none")]
        api_base: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// Pulumi ESC Environment (dynamic credentials via the ESC REST API)
    PulumiEsc {
        organization: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        project: Option<String>,
        environment: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        /// Optional filter: only surface these env var names from the ESC environment.
        /// When omitted, all `environmentVariables` entries are surfaced.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_vars: Option<Vec<String>>,
        /// Sigil character for single-pass reference interpolation. When set
        /// (e.g. `"%"`), any `<sigil>{path}` substring in a surfaced env var
        /// is replaced with the resolved leaf value from the environment
        /// (e.g. `%{anthropic.api_key}` → `properties.anthropic.value.api_key.value`).
        /// Missing references are a hard error. Single pass only — no recursion
        /// into the replaced text. Omit (default) to pass values through literally.
        #[serde(skip_serializing_if = "Option::is_none")]
        interpolate: Option<char>,
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
            LeaseBackendConfig::AwsSts { profile, .. } => aws_sts::check_prerequisites(profile),
            LeaseBackendConfig::GcpIam { .. } => gcp_iam::check_prerequisites(),
            LeaseBackendConfig::Vault { address, token, .. } => {
                vault::check_prerequisites(address, token)
            }
            LeaseBackendConfig::AzureToken { .. } => azure_token::check_prerequisites(),
            LeaseBackendConfig::Cloudflare { .. } => cloudflare::check_prerequisites(),
            LeaseBackendConfig::GithubApp {
                private_key_file, ..
            } => github_app::check_prerequisites(private_key_file),
            LeaseBackendConfig::PulumiEsc { .. } => pulumi_esc::check_prerequisites(),
            LeaseBackendConfig::Command { .. } => command::check_prerequisites(),
        }
    }

    /// Returns a list of (env_var_name, description) pairs for env vars the user
    /// can set to satisfy prerequisites. Used by `fnox lease create` to prompt
    /// interactively for missing credentials.
    pub fn required_env_vars(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            LeaseBackendConfig::AwsSts { .. } => aws_sts::required_env_vars(),
            LeaseBackendConfig::GcpIam { .. } => gcp_iam::required_env_vars(),
            LeaseBackendConfig::Vault { address, token, .. } => {
                vault::required_env_vars(address, token)
            }
            LeaseBackendConfig::AzureToken { .. } => azure_token::required_env_vars(),
            LeaseBackendConfig::Cloudflare { .. } => cloudflare::required_env_vars(),
            LeaseBackendConfig::GithubApp { .. } => github_app::required_env_vars(),
            LeaseBackendConfig::PulumiEsc { .. } => pulumi_esc::required_env_vars(),
            LeaseBackendConfig::Command { .. } => command::required_env_vars(),
        }
    }

    /// Zero-allocation check whether this backend produces the given env var key.
    pub fn produces_env_var(&self, key: &str) -> bool {
        match self {
            LeaseBackendConfig::AwsSts { .. } => aws_sts::PRODUCED_ENV_VARS.contains(&key),
            LeaseBackendConfig::GcpIam { env_var, .. } => env_var == key,
            LeaseBackendConfig::Vault { env_map, .. } => env_map.values().any(|v| v == key),
            LeaseBackendConfig::AzureToken { env_var, .. } => env_var == key,
            LeaseBackendConfig::Command { .. } => false,
            LeaseBackendConfig::Cloudflare { env_var, .. } => env_var == key,
            LeaseBackendConfig::GithubApp { env_var, .. } => env_var == key,
            LeaseBackendConfig::PulumiEsc { env_vars, .. } => env_vars
                .as_ref()
                .is_some_and(|vars| vars.iter().any(|v| v == key)),
        }
    }

    /// All env var names this backend may consume at runtime, including aliases.
    /// Used by `fnox get` to filter which profile secrets to resolve before
    /// creating a lease. Each backend defines its own `CONSUMED_ENV_VARS` constant
    /// covering both canonical names and runtime aliases.
    pub fn consumed_env_vars(&self) -> &'static [&'static str] {
        match self {
            LeaseBackendConfig::AwsSts { .. } => aws_sts::CONSUMED_ENV_VARS,
            LeaseBackendConfig::GcpIam { .. } => gcp_iam::CONSUMED_ENV_VARS,
            LeaseBackendConfig::Vault { .. } => vault::CONSUMED_ENV_VARS,
            LeaseBackendConfig::AzureToken { .. } => azure_token::CONSUMED_ENV_VARS,
            LeaseBackendConfig::Command { .. } => command::CONSUMED_ENV_VARS,
            LeaseBackendConfig::Cloudflare { .. } => cloudflare::CONSUMED_ENV_VARS,
            LeaseBackendConfig::GithubApp { .. } => github_app::CONSUMED_ENV_VARS,
            LeaseBackendConfig::PulumiEsc { .. } => pulumi_esc::CONSUMED_ENV_VARS,
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
                token_type,
                account_id,
                policies,
                env_var,
                ..
            } => Ok(Box::new(cloudflare::CloudflareBackend::new(
                token_type.clone(),
                account_id.clone(),
                policies.clone(),
                env_var.clone(),
            )?)),
            LeaseBackendConfig::GithubApp {
                app_id,
                installation_id,
                private_key_file,
                env_var,
                permissions,
                repositories,
                api_base,
                ..
            } => Ok(Box::new(github_app::GitHubAppBackend::new(
                app_id.clone(),
                installation_id.clone(),
                private_key_file.clone(),
                env_var.clone(),
                permissions.clone(),
                repositories.clone(),
                api_base.clone(),
            ))),
            LeaseBackendConfig::PulumiEsc {
                organization,
                project,
                environment,
                token,
                env_vars,
                interpolate,
                ..
            } => Ok(Box::new(pulumi_esc::PulumiEscBackend::new(
                organization.clone(),
                project.clone(),
                environment.clone(),
                token.clone(),
                env_vars.clone(),
                *interpolate,
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
            | LeaseBackendConfig::GithubApp { duration, .. }
            | LeaseBackendConfig::PulumiEsc { duration, .. }
            | LeaseBackendConfig::Command { duration, .. } => duration.as_deref(),
        }
    }
}
