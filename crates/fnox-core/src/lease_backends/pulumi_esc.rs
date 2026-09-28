use crate::error::Result;
use crate::lease_backends::{Lease, LeaseBackend};
use crate::pulumi_esc_api::{self, EscEnv};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/pulumi-esc";

pub const CONSUMED_ENV_VARS: &[&str] = pulumi_esc_api::ENV_VARS;

pub fn check_prerequisites(token: &Option<String>) -> Option<String> {
    pulumi_esc_api::resolve_auth(token.as_deref(), URL)
        .err()
        .map(|e| e.to_string())
}

pub fn required_env_vars(token: &Option<String>) -> Vec<(&'static str, &'static str)> {
    if token.is_some() {
        return vec![];
    }
    vec![("PULUMI_ACCESS_TOKEN", "Pulumi Cloud access token")]
}

pub struct PulumiEscBackend {
    env: EscEnv,
    env_vars: Option<Vec<String>>,
}

impl PulumiEscBackend {
    pub fn new(env: EscEnv, env_vars: Option<Vec<String>>) -> Self {
        Self { env, env_vars }
    }
}

#[async_trait]
impl LeaseBackend for PulumiEscBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let env_ref = self.env.env_ref();
        tracing::debug!(
            "Opening Pulumi ESC env '{}' (label='{}', duration={}s)",
            env_ref,
            label,
            duration.as_secs()
        );

        let body = self.env.open(duration, URL).await?;

        let env_vars_obj = body
            .pointer("/properties/environmentVariables/value")
            .and_then(|v| v.as_object())
            .ok_or_else(|| {
                pulumi_esc_api::invalid_response(
                    "Opened environment has no 'environmentVariables' block",
                    "Add an environmentVariables block to the ESC environment",
                    URL,
                )
            })?;

        let names: Vec<&String> = match &self.env_vars {
            Some(filter) => filter.iter().collect(),
            None => env_vars_obj.keys().collect(),
        };
        let mut credentials = IndexMap::new();
        for name in names {
            match env_vars_obj
                .get(name)
                .and_then(pulumi_esc_api::coerce_scalar)
            {
                Some(val) => {
                    credentials.insert(name.clone(), val);
                }
                None if self.env_vars.is_some() => {
                    tracing::warn!("Pulumi ESC env '{}' did not include '{}'", env_ref, name);
                }
                None => {}
            }
        }

        if credentials.is_empty() {
            return Err(pulumi_esc_api::invalid_response(
                "No environment variables surfaced from ESC environment",
                "Check the ESC environment defines environmentVariables and that 'env_vars' (if set) matches",
                URL,
            ));
        }

        let expires_at =
            Some(chrono::Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64));
        let lease_id = super::generate_lease_id(&format!("pulumi-esc-{env_ref}"));

        Ok(Lease {
            credentials,
            expires_at,
            lease_id,
        })
    }

    /// `duration` bounds only the ESC open session; credentials minted inside
    /// (e.g. `fn::open::aws-login`) keep their own lifetime, so a short cap
    /// limits how long a stale credential can sit in the ledger.
    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(3600)
    }
}
