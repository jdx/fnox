use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use crate::pulumi_esc_api::{self, EscClient, PROVIDER_NAME};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/pulumi-esc";

pub const CONSUMED_ENV_VARS: &[&str] = &[
    "PULUMI_ACCESS_TOKEN",
    "FNOX_PULUMI_ACCESS_TOKEN",
    "PULUMI_BACKEND_URL",
    "PULUMI_HOME",
];

pub fn check_prerequisites() -> Option<String> {
    pulumi_esc_api::resolve_auth().err()
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
    interpolate: Option<char>,
}

impl PulumiEscBackend {
    pub fn new(
        organization: String,
        project: Option<String>,
        environment: String,
        token: Option<String>,
        env_vars: Option<Vec<String>>,
        interpolate: Option<char>,
    ) -> Self {
        Self {
            organization,
            project,
            environment,
            token,
            env_vars,
            interpolate,
        }
    }

    fn env_ref(&self) -> String {
        pulumi_esc_api::build_env_ref(
            &self.organization,
            self.project.as_deref(),
            &self.environment,
        )
    }
}

/// Single-pass `<sigil>{path}` substitution against the resolved `properties`
/// tree. Scans left-to-right; the replacement text is NOT rescanned, so
/// `%{foo.%{bar}}` parses as `%{foo.%{bar}` (path `foo.%{bar`), which fails
/// lookup and errors. Any missing reference is a hard error.
fn resolve_refs(raw: &str, root: &serde_json::Value, sigil: char) -> Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    let open: String = format!("{sigil}{{");
    while let Some(start) = rest.find(&open) {
        out.push_str(&rest[..start]);
        let after_open = &rest[start + open.len()..];
        let end = after_open
            .find('}')
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Unterminated '{open}' in value: {raw}"),
                hint: "Add a closing '}' or disable `interpolate` in the lease config".to_string(),
                url: URL.to_string(),
            })?;
        let path = &after_open[..end];
        let resolved = pulumi_esc_api::lookup(root, path).ok_or_else(|| {
            FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Unresolved reference '{open}{path}}}' in value"),
                hint: "Check the path exists in this environment's `properties` tree".to_string(),
                url: URL.to_string(),
            }
        })?;
        out.push_str(&resolved);
        rest = &after_open[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[async_trait]
impl LeaseBackend for PulumiEscBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let env_ref = self.env_ref();
        tracing::debug!(
            "Opening Pulumi ESC env '{}' (label='{}', duration={}s)",
            env_ref,
            label,
            duration.as_secs()
        );

        let client = EscClient::new(self.token.as_deref(), URL)?;
        let body = client.open_and_read(&env_ref, duration).await?;

        let env_vars_obj = body
            .pointer("/properties/environmentVariables/value")
            .and_then(|v| v.as_object())
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: "Opened environment has no 'environmentVariables' block".to_string(),
                hint: "Add an environmentVariables block to the ESC environment".to_string(),
                url: URL.to_string(),
            })?;

        let mut credentials = IndexMap::new();
        match &self.env_vars {
            Some(filter) => {
                for name in filter {
                    match env_vars_obj
                        .get(name)
                        .and_then(pulumi_esc_api::coerce_scalar)
                    {
                        Some(val) => {
                            credentials.insert(name.clone(), val);
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
                for (name, wrapped) in env_vars_obj {
                    if let Some(val) = pulumi_esc_api::coerce_scalar(wrapped) {
                        credentials.insert(name.clone(), val);
                    }
                }
            }
        }

        if credentials.is_empty() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: "No environment variables surfaced from ESC environment".to_string(),
                hint: "Check the ESC environment defines environmentVariables and that 'env_vars' (if set) matches".to_string(),
                url: URL.to_string(),
            });
        }

        if let Some(sigil) = self.interpolate {
            for val in credentials.values_mut() {
                *val = resolve_refs(val, &body, sigil)?;
            }
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

    fn max_lease_duration(&self) -> Duration {
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
            None,
        );
        assert_eq!(b.env_ref(), "myorg/proj/dev");
    }

    #[test]
    fn env_ref_without_project() {
        let b = PulumiEscBackend::new("myorg".into(), None, "dev".into(), None, None, None);
        assert_eq!(b.env_ref(), "myorg/dev");
    }

    fn sample_body() -> serde_json::Value {
        serde_json::json!({
            "properties": {
                "anthropic": {
                    "value": { "api_key": { "value": "sk-test-123" } }
                },
                "aws": {
                    "value": { "region": { "value": "us-west-2" } }
                }
            }
        })
    }

    #[test]
    fn resolve_refs_basic_substitution() {
        let body = sample_body();
        let out = resolve_refs("key=%{anthropic.api_key};", &body, '%').unwrap();
        assert_eq!(out, "key=sk-test-123;");
    }

    #[test]
    fn resolve_refs_no_sigil_pass_through() {
        let body = sample_body();
        assert_eq!(
            resolve_refs("plain value", &body, '%').unwrap(),
            "plain value"
        );
    }

    #[test]
    fn resolve_refs_multiple_refs() {
        let body = sample_body();
        let out = resolve_refs("%{anthropic.api_key}|%{aws.region}", &body, '%').unwrap();
        assert_eq!(out, "sk-test-123|us-west-2");
    }

    #[test]
    fn resolve_refs_missing_is_error() {
        let body = sample_body();
        let err = resolve_refs("%{missing.path}", &body, '%').unwrap_err();
        assert!(matches!(err, FnoxError::ProviderInvalidResponse { .. }));
    }

    #[test]
    fn resolve_refs_unterminated_is_error() {
        let body = sample_body();
        let err = resolve_refs("%{anthropic.api_key", &body, '%').unwrap_err();
        assert!(matches!(err, FnoxError::ProviderInvalidResponse { .. }));
    }

    #[test]
    fn resolve_refs_is_single_pass_not_recursive() {
        let body = sample_body();
        let err = resolve_refs("%{foo.%{bar}}", &body, '%').unwrap_err();
        assert!(matches!(err, FnoxError::ProviderInvalidResponse { .. }));
    }

    #[test]
    fn resolve_refs_alternate_sigil() {
        let body = sample_body();
        assert_eq!(
            resolve_refs("${aws.region}", &body, '$').unwrap(),
            "us-west-2"
        );
    }
}
