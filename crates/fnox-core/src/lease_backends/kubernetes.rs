use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
use k8s_openapi::api::core::v1::ServiceAccount;
use kube::Api;
use kube::api::PostParams;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/kubernetes";
const PROVIDER: &str = "Kubernetes";

/// The API server rejects TokenRequests shorter than 10 minutes.
const MIN_DURATION_SECS: u64 = 600;
const MAX_DURATION_SECS: u64 = 24 * 3600;

/// All env var names the Kubernetes backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = &["KUBECONFIG"];

pub fn check_prerequisites() -> Option<String> {
    // Access comes from a kubeconfig or the in-cluster service account, and
    // either can only be validated by connecting.
    None
}

pub fn required_env_vars() -> Vec<(&'static str, &'static str)> {
    vec![]
}

pub struct KubernetesBackend {
    service_account: String,
    namespace: Option<String>,
    audiences: Vec<String>,
    context: Option<String>,
    kubeconfig: Option<String>,
    env_var: String,
}

impl KubernetesBackend {
    pub fn new(
        service_account: String,
        namespace: Option<String>,
        audiences: Vec<String>,
        context: Option<String>,
        kubeconfig: Option<String>,
        env_var: String,
    ) -> Self {
        Self {
            service_account,
            namespace: namespace.filter(|namespace| !namespace.trim().is_empty()),
            audiences,
            context: context.filter(|context| !context.trim().is_empty()),
            kubeconfig: kubeconfig.filter(|path| !path.trim().is_empty()),
            env_var,
        }
    }

    fn api_error(&self, namespace: &str, error: kube::Error) -> FnoxError {
        match error {
            kube::Error::Api(response) if matches!(response.code, 401 | 403) => {
                FnoxError::ProviderAuthFailed {
                    provider: PROVIDER.to_string(),
                    details: response.message,
                    hint: format!(
                        "Grant 'create' on 'serviceaccounts/token' for '{}' in namespace '{namespace}', and check the selected kubeconfig/context",
                        self.service_account
                    ),
                    url: URL.to_string(),
                }
            }
            kube::Error::Api(response) if response.code == 404 => FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: response.message,
                hint: format!(
                    "Check that ServiceAccount '{}' exists in namespace '{namespace}'",
                    self.service_account
                ),
                url: URL.to_string(),
            },
            kube::Error::Api(response) => FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: response.message,
                hint: "The API server rejected the token request; check duration and audiences"
                    .to_string(),
                url: URL.to_string(),
            },
            other => FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: other.to_string(),
                hint: "Check Kubernetes API reachability and the selected kubeconfig/context"
                    .to_string(),
                url: URL.to_string(),
            },
        }
    }
}

#[async_trait]
impl LeaseBackend for KubernetesBackend {
    async fn create_lease(&self, duration: Duration, _label: &str) -> Result<Lease> {
        if duration.as_secs() < MIN_DURATION_SECS {
            return Err(FnoxError::Config(format!(
                "Kubernetes tokens must last at least 10m, but the lease duration is {}s. \
                 Set a longer 'duration'.",
                duration.as_secs()
            )));
        }

        let (client, default_namespace) =
            crate::providers::kubernetes::connect(self.context.clone(), self.kubeconfig.as_deref())
                .await
                .ok_or_else(|| FnoxError::ProviderApiError {
                    provider: PROVIDER.to_string(),
                    details: "Unable to load Kubernetes client configuration".to_string(),
                    hint: "Check the configured kubeconfig/context, or run where in-cluster service account authentication is available".to_string(),
                    url: URL.to_string(),
                })?;
        let namespace = self.namespace.clone().unwrap_or(default_namespace);

        let request = TokenRequest {
            spec: TokenRequestSpec {
                audiences: self.audiences.clone(),
                expiration_seconds: Some(duration.as_secs() as i64),
                ..Default::default()
            },
            ..Default::default()
        };
        let api: Api<ServiceAccount> = Api::namespaced(client, &namespace);
        let response = api
            .create_token_request(&self.service_account, &PostParams::default(), &request)
            .await
            .map_err(|e| self.api_error(&namespace, e))?;

        let status = response
            .status
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER.to_string(),
                details: "Response missing 'status'".to_string(),
                hint: "Unexpected response from the Kubernetes API server".to_string(),
                url: URL.to_string(),
            })?;

        // The API server may grant a different lifetime than requested, so
        // record the expiry it reports.
        let expires_at =
            chrono::DateTime::from_timestamp(status.expiration_timestamp.0.as_second(), 0)
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: PROVIDER.to_string(),
                    details: "Response has an invalid 'expirationTimestamp'".to_string(),
                    hint: "Unexpected response from the Kubernetes API server".to_string(),
                    url: URL.to_string(),
                })?;

        let mut credentials = IndexMap::new();
        credentials.insert(self.env_var.clone(), status.token);

        Ok(Lease {
            credentials,
            expires_at: Some(expires_at),
            lease_id: super::generate_lease_id("kubernetes"),
        })
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(MAX_DURATION_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_durations_the_api_server_would_refuse() {
        let backend = KubernetesBackend::new(
            "deployer".to_string(),
            None,
            vec![],
            None,
            None,
            "KUBE_TOKEN".to_string(),
        );
        let err = backend
            .create_lease(Duration::from_secs(300), "label")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("at least 10m"), "{err}");
    }

    #[test]
    fn blank_overrides_are_ignored() {
        let backend = KubernetesBackend::new(
            "deployer".to_string(),
            Some(" ".to_string()),
            vec![],
            Some(String::new()),
            Some("  ".to_string()),
            "KUBE_TOKEN".to_string(),
        );
        assert!(backend.namespace.is_none());
        assert!(backend.context.is_none());
        assert!(backend.kubeconfig.is_none());
    }
}
