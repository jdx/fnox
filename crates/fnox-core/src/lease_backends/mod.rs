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
pub mod github_oauth;
pub mod gitlab;
pub mod kubernetes;
pub mod oauth2_client_credentials;
pub mod tailscale;
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

    /// Whether a lease's credentials may be cached and handed to later
    /// commands. Backends whose credentials are consumed by their first use
    /// (such as a single-use auth key) return false, so every command gets a
    /// fresh lease and nothing sensitive is stored in the ledger.
    fn cacheable(&self) -> bool {
        true
    }
}

/// Read a credential from the environment. An empty value counts as unset, so
/// `FOO=` cannot shadow a usable alternative or pass for a real credential.
pub(crate) fn env_credential(name: &str) -> Option<String> {
    crate::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Reject a URL that would send credentials in cleartext. Only https is
/// accepted, except for loopback hosts, which never leave the machine (local
/// proxies and test servers).
pub(crate) fn require_secure_url(backend: &str, field: &str, value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).map_err(|e| {
        crate::error::FnoxError::Config(format!(
            "{backend} backend: invalid {field} '{value}': {e}"
        ))
    })?;
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback => Ok(()),
        _ => Err(crate::error::FnoxError::Config(format!(
            "{backend} backend: {field} must use https (http is allowed only for localhost, \
             127.0.0.1 or ::1), got '{value}'."
        ))),
    }
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

fn default_github_oauth_auth_base() -> String {
    "https://github.com/login/oauth".to_string()
}

fn default_github_oauth_api_base() -> String {
    "https://api.github.com".to_string()
}

fn default_github_oauth_scope() -> String {
    "repo read:org workflow".to_string()
}

fn default_github_oauth_keyring_service() -> String {
    "fnox-github-oauth".to_string()
}

fn default_gitlab_scopes() -> Vec<String> {
    vec!["read_api".to_string()]
}

fn default_gitlab_access_level() -> String {
    "developer".to_string()
}

fn default_gitlab_env_var() -> String {
    "GITLAB_TOKEN".to_string()
}

fn default_kubernetes_env_var() -> String {
    "KUBE_TOKEN".to_string()
}

fn default_oauth2_env_var() -> String {
    "OAUTH2_ACCESS_TOKEN".to_string()
}

fn default_tailscale_tailnet() -> String {
    "-".to_string()
}

fn default_tailscale_env_var() -> String {
    "TS_AUTHKEY".to_string()
}

fn default_true() -> bool {
    true
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
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_command: Option<String>,
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
        /// "default" (service principal env vars, then Azure CLI login) or "managed-identity"
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<String>,
        /// Client ID of a user-assigned managed identity; requires `auth = "managed-identity"`
        #[serde(default, skip_serializing_if = "Option::is_none")]
        managed_identity_client_id: Option<String>,
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
    /// GitHub App User Access Token via OAuth Device Flow
    GithubOauth {
        client_id: String,
        /// OAuth scope string requested from GitHub.
        #[serde(default = "default_github_oauth_scope")]
        scope: String,
        #[serde(default = "default_github_env_var")]
        env_var: String,
        /// OS keyring service used to cache access/refresh tokens.
        #[serde(default = "default_github_oauth_keyring_service")]
        keyring_service: String,
        /// Disable to force device flow on each lease creation.
        #[serde(default = "default_true")]
        keyring_cache: bool,
        /// Open the verification URL in a browser when possible.
        #[serde(default = "default_true")]
        open_browser: bool,
        /// OAuth token endpoint base URL (default: https://github.com/login/oauth)
        #[serde(default = "default_github_oauth_auth_base")]
        auth_base: String,
        /// GitHub API base URL (default: https://api.github.com)
        #[serde(default = "default_github_oauth_api_base")]
        api_base: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// GitLab Project or Group Access Token
    Gitlab {
        /// GitLab base URL (default: https://gitlab.com)
        #[serde(skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        /// Project ID or full path; set exactly one of `project` or `group`
        #[serde(skip_serializing_if = "Option::is_none")]
        project: Option<String>,
        /// Group ID or full path; set exactly one of `project` or `group`
        #[serde(skip_serializing_if = "Option::is_none")]
        group: Option<String>,
        #[serde(default = "default_gitlab_scopes")]
        scopes: Vec<String>,
        /// "guest", "reporter", "developer" (default), "maintainer" or "owner"
        #[serde(default = "default_gitlab_access_level")]
        access_level: String,
        #[serde(default = "default_gitlab_env_var")]
        env_var: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// Kubernetes ServiceAccount Token (TokenRequest)
    Kubernetes {
        service_account: String,
        /// ServiceAccount namespace (default: the kubeconfig context's namespace)
        #[serde(skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        audiences: Vec<String>,
        /// kubeconfig context (default: the current context)
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
        /// Path to a kubeconfig file (default: KUBECONFIG, then ~/.kube/config)
        #[serde(skip_serializing_if = "Option::is_none")]
        kubeconfig: Option<String>,
        #[serde(default = "default_kubernetes_env_var")]
        env_var: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// OAuth2 Client Credentials Grant
    Oauth2ClientCredentials {
        token_url: String,
        client_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(default = "default_oauth2_env_var")]
        env_var: String,
        /// "basic" (default) sends the credentials in a header, "post" in the form body
        #[serde(default)]
        auth_method: oauth2_client_credentials::ClientAuthMethod,
        /// Extra form parameters sent to the token endpoint
        #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
        params: IndexMap<String, String>,
        /// RFC 7009 revocation endpoint; tokens expire on their own when unset
        #[serde(skip_serializing_if = "Option::is_none")]
        revocation_url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<String>,
    },
    /// Tailscale Auth Key
    Tailscale {
        /// Tailnet name (default: "-", the tailnet the credentials belong to)
        #[serde(default = "default_tailscale_tailnet")]
        tailnet: String,
        /// Tailscale API base URL (default: https://api.tailscale.com)
        #[serde(skip_serializing_if = "Option::is_none")]
        api_base: Option<String>,
        /// ACL tags applied to devices that use the key, such as "tag:ci"
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tags: Vec<String>,
        #[serde(default)]
        reusable: bool,
        #[serde(default = "default_true")]
        ephemeral: bool,
        #[serde(default = "default_true")]
        preauthorized: bool,
        #[serde(default = "default_tailscale_env_var")]
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
            LeaseBackendConfig::AwsSts { profile, .. } => aws_sts::check_prerequisites(profile),
            LeaseBackendConfig::GcpIam { .. } => gcp_iam::check_prerequisites(),
            LeaseBackendConfig::Vault {
                address,
                token,
                credential_command,
                ..
            } => vault::check_prerequisites(address, token, credential_command),
            LeaseBackendConfig::AzureToken {
                auth,
                managed_identity_client_id,
                ..
            } => azure_token::check_prerequisites(auth.as_deref(), managed_identity_client_id),
            LeaseBackendConfig::Cloudflare { .. } => cloudflare::check_prerequisites(),
            LeaseBackendConfig::GithubApp {
                private_key_file, ..
            } => github_app::check_prerequisites(private_key_file),
            LeaseBackendConfig::GithubOauth { .. } => github_oauth::check_prerequisites(),
            LeaseBackendConfig::Gitlab { .. } => gitlab::check_prerequisites(),
            LeaseBackendConfig::Kubernetes { .. } => kubernetes::check_prerequisites(),
            LeaseBackendConfig::Oauth2ClientCredentials { .. } => {
                oauth2_client_credentials::check_prerequisites()
            }
            LeaseBackendConfig::Tailscale { .. } => tailscale::check_prerequisites(),
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
            LeaseBackendConfig::Vault {
                address,
                token,
                credential_command,
                ..
            } => vault::required_env_vars(address, token, credential_command),
            LeaseBackendConfig::AzureToken { auth, .. } => {
                azure_token::required_env_vars(auth.as_deref())
            }
            LeaseBackendConfig::Cloudflare { .. } => cloudflare::required_env_vars(),
            LeaseBackendConfig::GithubApp { .. } => github_app::required_env_vars(),
            LeaseBackendConfig::GithubOauth { .. } => github_oauth::required_env_vars(),
            LeaseBackendConfig::Gitlab { .. } => gitlab::required_env_vars(),
            LeaseBackendConfig::Kubernetes { .. } => kubernetes::required_env_vars(),
            LeaseBackendConfig::Oauth2ClientCredentials { .. } => {
                oauth2_client_credentials::required_env_vars()
            }
            LeaseBackendConfig::Tailscale { .. } => tailscale::required_env_vars(),
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
            LeaseBackendConfig::GithubOauth { env_var, .. } => env_var == key,
            LeaseBackendConfig::Gitlab { env_var, .. }
            | LeaseBackendConfig::Kubernetes { env_var, .. }
            | LeaseBackendConfig::Oauth2ClientCredentials { env_var, .. }
            | LeaseBackendConfig::Tailscale { env_var, .. } => env_var == key,
        }
    }

    /// Every env var name this backend produces. Empty for `command` backends,
    /// whose keys are only known after the command runs.
    pub fn produced_env_vars(&self) -> Vec<&str> {
        match self {
            LeaseBackendConfig::AwsSts { .. } => aws_sts::PRODUCED_ENV_VARS.to_vec(),
            LeaseBackendConfig::GcpIam { env_var, .. }
            | LeaseBackendConfig::AzureToken { env_var, .. }
            | LeaseBackendConfig::Cloudflare { env_var, .. }
            | LeaseBackendConfig::GithubApp { env_var, .. }
            | LeaseBackendConfig::GithubOauth { env_var, .. }
            | LeaseBackendConfig::Gitlab { env_var, .. }
            | LeaseBackendConfig::Kubernetes { env_var, .. }
            | LeaseBackendConfig::Oauth2ClientCredentials { env_var, .. }
            | LeaseBackendConfig::Tailscale { env_var, .. } => vec![env_var.as_str()],
            LeaseBackendConfig::Vault { env_map, .. } => {
                env_map.values().map(String::as_str).collect()
            }
            LeaseBackendConfig::Command { .. } => Vec::new(),
        }
    }

    /// Whether `consumed_env_vars` lists every secret this backend may read.
    /// A `command` backend runs a script that may read any environment variable.
    pub fn has_known_inputs(&self) -> bool {
        !matches!(self, LeaseBackendConfig::Command { .. })
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
            LeaseBackendConfig::AzureToken { auth, .. } => {
                azure_token::consumed_env_vars(auth.as_deref())
            }
            LeaseBackendConfig::Command { .. } => command::CONSUMED_ENV_VARS,
            LeaseBackendConfig::Cloudflare { .. } => cloudflare::CONSUMED_ENV_VARS,
            LeaseBackendConfig::GithubApp { .. } => github_app::CONSUMED_ENV_VARS,
            LeaseBackendConfig::GithubOauth { .. } => github_oauth::CONSUMED_ENV_VARS,
            LeaseBackendConfig::Gitlab { .. } => gitlab::CONSUMED_ENV_VARS,
            LeaseBackendConfig::Kubernetes { .. } => kubernetes::CONSUMED_ENV_VARS,
            LeaseBackendConfig::Oauth2ClientCredentials { .. } => {
                oauth2_client_credentials::CONSUMED_ENV_VARS
            }
            LeaseBackendConfig::Tailscale { .. } => tailscale::CONSUMED_ENV_VARS,
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
                credential_command,
                secret_path,
                namespace,
                env_map,
                method,
                ..
            } => Ok(Box::new(vault::VaultBackend::new(
                address.clone(),
                token.clone(),
                credential_command.clone(),
                secret_path.clone(),
                namespace.clone(),
                env_map.clone(),
                method.clone(),
            )?)),
            LeaseBackendConfig::AzureToken {
                scope,
                env_var,
                auth,
                managed_identity_client_id,
                ..
            } => Ok(Box::new(azure_token::AzureTokenBackend::new(
                scope.clone(),
                env_var.clone(),
                auth.as_deref(),
                managed_identity_client_id.clone(),
            )?)),
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
            LeaseBackendConfig::GithubOauth {
                client_id,
                scope,
                env_var,
                keyring_service,
                keyring_cache,
                open_browser,
                auth_base,
                api_base,
                ..
            } => Ok(Box::new(github_oauth::GitHubOauthBackend::new(
                client_id.clone(),
                scope.clone(),
                env_var.clone(),
                keyring_service.clone(),
                *keyring_cache,
                *open_browser,
                auth_base.clone(),
                api_base.clone(),
            ))),
            LeaseBackendConfig::Gitlab {
                url,
                project,
                group,
                scopes,
                access_level,
                env_var,
                ..
            } => Ok(Box::new(gitlab::GitLabBackend::new(
                url.clone(),
                project.clone(),
                group.clone(),
                scopes.clone(),
                access_level,
                env_var.clone(),
            )?)),
            LeaseBackendConfig::Kubernetes {
                service_account,
                namespace,
                audiences,
                context,
                kubeconfig,
                env_var,
                ..
            } => Ok(Box::new(kubernetes::KubernetesBackend::new(
                service_account.clone(),
                namespace.clone(),
                audiences.clone(),
                context.clone(),
                kubeconfig.clone(),
                env_var.clone(),
            ))),
            LeaseBackendConfig::Oauth2ClientCredentials {
                token_url,
                client_id,
                scope,
                audience,
                env_var,
                auth_method,
                params,
                revocation_url,
                ..
            } => Ok(Box::new(
                oauth2_client_credentials::Oauth2ClientCredentialsBackend::new(
                    token_url.clone(),
                    client_id.clone(),
                    scope.clone(),
                    audience.clone(),
                    env_var.clone(),
                    *auth_method,
                    params.clone(),
                    revocation_url.clone(),
                )?,
            )),
            LeaseBackendConfig::Tailscale {
                tailnet,
                api_base,
                tags,
                reusable,
                ephemeral,
                preauthorized,
                env_var,
                ..
            } => Ok(Box::new(tailscale::TailscaleBackend::new(
                tailnet.clone(),
                api_base.clone(),
                tags.clone(),
                *reusable,
                *ephemeral,
                *preauthorized,
                env_var.clone(),
            )?)),
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
            | LeaseBackendConfig::GithubOauth { duration, .. }
            | LeaseBackendConfig::Gitlab { duration, .. }
            | LeaseBackendConfig::Kubernetes { duration, .. }
            | LeaseBackendConfig::Oauth2ClientCredentials { duration, .. }
            | LeaseBackendConfig::Tailscale { duration, .. }
            | LeaseBackendConfig::Command { duration, .. } => duration.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> Vec<LeaseBackendConfig> {
        [
            "type = \"aws-sts\"\nregion = \"us-east-1\"\nrole_arn = \"arn:aws:iam::1:role/r\"",
            "type = \"gcp-iam\"\nservice_account_email = \"sa@p.iam.gserviceaccount.com\"\nenv_var = \"GCP_TOKEN\"",
            "type = \"vault\"\nsecret_path = \"aws/creds/r\"\n[env_map]\naccess_key = \"VAULT_AK\"\nsecret_key = \"VAULT_SK\"",
            "type = \"azure-token\"\nscope = \"https://management.azure.com/.default\"\nenv_var = \"AZ_TOKEN\"",
            "type = \"cloudflare\"\nenv_var = \"CF_TOKEN\"",
            "type = \"github-app\"\napp_id = \"1\"\ninstallation_id = \"2\"\nenv_var = \"GH_APP_TOKEN\"",
            "type = \"github-oauth\"\nclient_id = \"cid\"\nenv_var = \"GH_OAUTH_TOKEN\"",
            "type = \"gitlab\"\nproject = \"group/app\"\nenv_var = \"GL_TOKEN\"",
            "type = \"kubernetes\"\nservice_account = \"deployer\"\nenv_var = \"K8S_TOKEN\"",
            "type = \"oauth2-client-credentials\"\ntoken_url = \"https://idp.example.com/token\"\nclient_id = \"cid\"\nenv_var = \"OAUTH_TOKEN\"",
            "type = \"tailscale\"\nenv_var = \"TS_KEY\"",
            "type = \"command\"\ncreate_command = \"true\"",
        ]
        .iter()
        .map(|toml| toml_edit::de::from_str(toml).unwrap())
        .collect()
    }

    #[test]
    fn produced_env_vars_agrees_with_produces_env_var() {
        let probes = [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "GCP_TOKEN",
            "VAULT_AK",
            "VAULT_SK",
            "access_key",
            "AZ_TOKEN",
            "CF_TOKEN",
            "GH_APP_TOKEN",
            "GH_OAUTH_TOKEN",
            "GITHUB_TOKEN",
            "GL_TOKEN",
            "K8S_TOKEN",
            "OAUTH_TOKEN",
            "TS_KEY",
            "MY_TOKEN",
            "",
        ];
        for lease in fixtures() {
            let produced = lease.produced_env_vars();
            for probe in probes {
                assert_eq!(
                    produced.contains(&probe),
                    lease.produces_env_var(probe),
                    "{lease:?} disagrees on {probe:?}"
                );
            }
            for key in &produced {
                assert!(lease.produces_env_var(key));
            }
        }
    }

    #[test]
    fn secure_url_requires_https_except_on_loopback() {
        for ok in [
            "https://gitlab.example.com",
            "http://localhost:8080",
            "http://127.0.0.1:9",
            "http://[::1]:9/path",
        ] {
            assert!(require_secure_url("Test", "url", ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://gitlab.example.com",
            "http://10.0.0.5",
            "ftp://localhost",
            "not a url",
            "",
        ] {
            assert!(require_secure_url("Test", "url", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_command_backends_have_unknown_inputs() {
        for lease in fixtures() {
            assert_eq!(
                lease.has_known_inputs(),
                !matches!(lease, LeaseBackendConfig::Command { .. })
            );
        }
    }

    #[test]
    fn command_backends_produce_no_statically_known_keys() {
        let fixtures = fixtures();
        let command = fixtures.last().unwrap();
        assert!(command.produced_env_vars().is_empty());
    }
}
