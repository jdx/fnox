use crate::env;
use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::time::Duration;
use tokio::process::Command;

const URL: &str = "https://fnox.jdx.dev/leases/pulumi-esc";
const CLI: &str = "esc";

/// All env var names the Pulumi ESC backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = &["PULUMI_ACCESS_TOKEN", "FNOX_PULUMI_ACCESS_TOKEN"];

pub fn check_prerequisites() -> Option<String> {
    if std::env::var("PULUMI_ACCESS_TOKEN").is_ok()
        || std::env::var("FNOX_PULUMI_ACCESS_TOKEN").is_ok()
    {
        return None;
    }
    if which::which(CLI).is_err() {
        return Some(format!(
            "{} CLI not found. Install: brew install pulumi/tap/esc",
            CLI
        ));
    }
    Some(
        "Pulumi ESC credentials not found. Run 'esc login' or set PULUMI_ACCESS_TOKEN.".to_string(),
    )
}

pub fn required_env_vars() -> Vec<(&'static str, &'static str)> {
    vec![("PULUMI_ACCESS_TOKEN", "Pulumi Cloud access token")]
}

pub struct PulumiEscBackend {
    organization: String,
    project: Option<String>,
    environment: String,
    token: Option<String>,
    env_vars: Option<Vec<String>>,
}

impl PulumiEscBackend {
    pub fn new(
        organization: String,
        project: Option<String>,
        environment: String,
        token: Option<String>,
        env_vars: Option<Vec<String>>,
    ) -> Self {
        Self {
            organization,
            project,
            environment,
            token,
            env_vars,
        }
    }

    fn env_ref(&self) -> String {
        match &self.project {
            Some(project) => format!("{}/{}/{}", self.organization, project, self.environment),
            None => format!("{}/{}", self.organization, self.environment),
        }
    }

    fn resolve_token(&self) -> Option<String> {
        self.token.clone().or_else(|| {
            env::var("FNOX_PULUMI_ACCESS_TOKEN")
                .or_else(|_| env::var("PULUMI_ACCESS_TOKEN"))
                .ok()
        })
    }
}

#[async_trait]
impl LeaseBackend for PulumiEscBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        tracing::debug!(
            "Creating Pulumi ESC lease for env '{}' (label='{}', duration={}s)",
            self.env_ref(),
            label,
            duration.as_secs()
        );

        let env_ref = self.env_ref();
        let mut cmd = Command::new(CLI);
        cmd.args(["env", "open", &env_ref, "--format", "json"]);
        if let Some(token) = self.resolve_token() {
            cmd.env("PULUMI_ACCESS_TOKEN", token);
        }
        cmd.stdin(std::process::Stdio::null());

        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "Pulumi ESC".to_string(),
                    cli: CLI.to_string(),
                    install_hint: "brew install pulumi/tap/esc".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "Pulumi ESC".to_string(),
                    details: e.to_string(),
                    hint: "Check that the esc CLI is installed and accessible".to_string(),
                    url: URL.to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let lower = stderr.to_lowercase();
            if lower.contains("unauthorized")
                || lower.contains("401")
                || lower.contains("403")
                || lower.contains("access token")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "Pulumi ESC".to_string(),
                    details: stderr,
                    hint: "Run 'esc login' or set PULUMI_ACCESS_TOKEN".to_string(),
                    url: URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderApiError {
                provider: "Pulumi ESC".to_string(),
                details: stderr,
                hint: "Check organization/project/environment in your lease config".to_string(),
                url: URL.to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Pulumi ESC".to_string(),
                details: format!("Invalid UTF-8 in esc output: {}", e),
                hint: "Unexpected non-UTF8 output from esc".to_string(),
                url: URL.to_string(),
            })?;

        let root: serde_json::Value =
            serde_json::from_str(&stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "Pulumi ESC".to_string(),
                details: format!("Failed to parse esc JSON: {}", e),
                hint: "Unexpected response format from 'esc env open --format json'".to_string(),
                url: URL.to_string(),
            })?;

        let env_vars_obj = root
            .get("environmentVariables")
            .and_then(|v| v.as_object())
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "Pulumi ESC".to_string(),
                details: "Opened environment has no 'environmentVariables' section".to_string(),
                hint:
                    "Add environment variables to the ESC environment's environmentVariables block"
                        .to_string(),
                url: URL.to_string(),
            })?;

        let mut credentials = IndexMap::new();
        match &self.env_vars {
            Some(filter) => {
                for name in filter {
                    match env_vars_obj.get(name).and_then(|v| v.as_str()) {
                        Some(val) => {
                            credentials.insert(name.clone(), val.to_string());
                        }
                        None => {
                            tracing::warn!(
                                "Pulumi ESC env '{}' did not include '{}'",
                                env_ref,
                                name
                            );
                        }
                    }
                }
            }
            None => {
                for (name, value) in env_vars_obj {
                    if let Some(val) = value.as_str() {
                        credentials.insert(name.clone(), val.to_string());
                    }
                }
            }
        }

        if credentials.is_empty() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "Pulumi ESC".to_string(),
                details: "No environment variables surfaced from ESC environment".to_string(),
                hint: "Check the ESC environment defines environmentVariables and that 'env_vars' (if set) matches".to_string(),
                url: URL.to_string(),
            });
        }

        // ESC doesn't expose a single expiration — dynamic credentials are
        // already short-lived per their underlying integration. Use the
        // requested duration as an advisory expiry so the ledger reissues.
        let expires_at =
            Some(chrono::Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64));
        let lease_id = super::generate_lease_id(&format!("pulumi-esc-{}", env_ref));

        Ok(Lease {
            credentials,
            expires_at,
            lease_id,
        })
    }

    fn max_lease_duration(&self) -> Duration {
        // ESC-minted dynamic credentials are bounded by the underlying integration
        // (e.g., AWS OIDC caps at 1h by default). Cap at 1h as a safe ceiling.
        Duration::from_secs(3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ref_with_project() {
        let b = PulumiEscBackend::new(
            "myorg".into(),
            Some("proj".into()),
            "dev".into(),
            None,
            None,
        );
        assert_eq!(b.env_ref(), "myorg/proj/dev");
    }

    #[test]
    fn env_ref_without_project() {
        let b = PulumiEscBackend::new("myorg".into(), None, "dev".into(), None, None);
        assert_eq!(b.env_ref(), "myorg/dev");
    }
}
