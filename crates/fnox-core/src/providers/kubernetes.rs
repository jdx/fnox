use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use futures::{StreamExt, stream};
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, Config,
    config::{KubeConfigOptions, Kubeconfig},
};
use std::collections::HashMap;

const PROVIDER_NAME: &str = "Kubernetes Secrets";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/kubernetes";

pub struct KubernetesProvider {
    context: Option<String>,
    namespace: Option<String>,
    kubeconfig: Option<String>,
    prefix: Option<String>,
}

#[derive(Debug)]
struct SecretReference {
    namespace: Option<String>,
    name: String,
    key: Option<String>,
}

#[derive(Debug)]
struct RequestedValue {
    environment_key: String,
    data_key: Option<String>,
}

impl KubernetesProvider {
    pub fn new(
        context: Option<String>,
        namespace: Option<String>,
        kubeconfig: Option<String>,
        prefix: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            context: non_empty(context),
            namespace: non_empty(namespace),
            kubeconfig: non_empty(kubeconfig),
            prefix: non_empty(prefix),
        })
    }

    fn selected_context(&self) -> Option<String> {
        selected_context(
            self.context.as_deref(),
            env::var("FNOX_K8S_CONTEXT").ok().as_deref(),
        )
    }

    async fn client_and_namespace(&self) -> Result<(Client, String)> {
        let options = KubeConfigOptions {
            context: self.selected_context(),
            ..KubeConfigOptions::default()
        };

        let config = match &self.kubeconfig {
            Some(path) => {
                let kubeconfig = Kubeconfig::read_from(path).map_err(|_| config_error())?;
                Config::from_custom_kubeconfig(kubeconfig, &options)
                    .await
                    .map_err(|_| config_error())?
            }
            None if options.context.is_some() => Config::from_kubeconfig(&options)
                .await
                .map_err(|_| config_error())?,
            // An explicit KUBECONFIG must not fall back to an in-cluster identity
            // when it cannot be loaded. That could select a different cluster.
            None if has_non_empty_value(env::var("KUBECONFIG").ok().as_deref()) => {
                Config::from_kubeconfig(&options)
                    .await
                    .map_err(|_| config_error())?
            }
            None => Config::infer().await.map_err(|_| config_error())?,
        };

        let namespace = self
            .namespace
            .clone()
            .filter(|namespace| !namespace.is_empty())
            .unwrap_or_else(|| config.default_namespace.clone());
        let client = Client::try_from(config).map_err(|_| config_error())?;

        Ok((client, namespace))
    }

    fn secret_name(&self, name: &str) -> String {
        self.prefix
            .as_ref()
            .map_or_else(|| name.to_string(), |prefix| format!("{prefix}{name}"))
    }

    async fn resolve_batch_with_client(
        &self,
        client: Client,
        default_namespace: String,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let mut results = HashMap::with_capacity(secrets.len());
        let mut requested: HashMap<(String, String), Vec<RequestedValue>> = HashMap::new();

        for (environment_key, reference) in secrets {
            let reference = match parse_reference(reference) {
                Ok(reference) => reference,
                Err(error) => {
                    results.insert(environment_key.clone(), Err(error));
                    continue;
                }
            };
            let namespace = reference
                .namespace
                .unwrap_or_else(|| default_namespace.clone());
            let secret_name = self.secret_name(&reference.name);
            requested
                .entry((namespace, secret_name))
                .or_default()
                .push(RequestedValue {
                    environment_key: environment_key.clone(),
                    data_key: reference.key,
                });
        }

        let requests = stream::iter(requested)
            .map(|((namespace, secret_name), values)| {
                let client = &client;
                async move {
                    let secret = get_secret(client, &namespace, &secret_name).await;
                    (namespace, secret_name, values, secret)
                }
            })
            .buffer_unordered(10);
        futures::pin_mut!(requests);
        while let Some((namespace, secret_name, values, secret)) = requests.next().await {
            for value in values {
                let result = match &secret {
                    Ok(secret) => read_secret_value(
                        secret,
                        &namespace,
                        &secret_name,
                        value.data_key.as_deref(),
                    ),
                    Err(error) => Err(copy_error(error)),
                };
                results.insert(value.environment_key, result);
            }
        }

        results
    }
}

#[async_trait]
impl crate::providers::Provider for KubernetesProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        let values = self
            .get_secrets_batch(&[("KUBERNETES_SECRET".to_string(), value.to_string())])
            .await;
        values.into_values().next().unwrap_or_else(|| {
            Err(invalid_reference(
                "A Kubernetes Secret reference is required",
            ))
        })
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        if secrets.is_empty() {
            return HashMap::new();
        }

        let (client, namespace) = match self.client_and_namespace().await {
            Ok(client_and_namespace) => client_and_namespace,
            Err(error) => {
                return secrets
                    .iter()
                    .map(|(environment_key, _)| (environment_key.clone(), Err(copy_error(&error))))
                    .collect();
            }
        };

        self.resolve_batch_with_client(client, namespace, secrets)
            .await
    }

    async fn test_connection(&self) -> Result<()> {
        // Do not list or probe Secrets: loading the client validates configuration only.
        let _ = self.client_and_namespace().await?;
        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

fn selected_context(configured: Option<&str>, environment: Option<&str>) -> Option<String> {
    configured
        .filter(|value| !value.trim().is_empty())
        .or_else(|| environment.filter(|value| !value.trim().is_empty()))
        .map(str::to_owned)
}

fn has_non_empty_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

fn parse_reference(value: &str) -> Result<SecretReference> {
    let segments: Vec<_> = value.split('/').collect();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(invalid_reference(
            "Use secret, secret/key, or namespace/secret/key without empty segments",
        ));
    }

    match segments.as_slice() {
        [name] => Ok(SecretReference {
            namespace: None,
            name: (*name).to_string(),
            key: None,
        }),
        [name, key] => Ok(SecretReference {
            namespace: None,
            name: (*name).to_string(),
            key: Some((*key).to_string()),
        }),
        [namespace, name, key] => Ok(SecretReference {
            namespace: Some((*namespace).to_string()),
            name: (*name).to_string(),
            key: Some((*key).to_string()),
        }),
        _ => Err(invalid_reference(
            "Use secret, secret/key, or namespace/secret/key",
        )),
    }
}

async fn get_secret(client: &Client, namespace: &str, name: &str) -> Result<Secret> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    api.get(name)
        .await
        .map_err(|error| kubernetes_error(error, namespace, name))
}

fn read_secret_value(
    secret: &Secret,
    namespace: &str,
    secret_name: &str,
    requested_key: Option<&str>,
) -> Result<String> {
    let data = secret
        .data
        .as_ref()
        .filter(|data| !data.is_empty())
        .ok_or_else(|| no_secret_data_error(namespace, secret_name))?;

    let (key, value) = match requested_key {
        Some(key) => data.get(key).map(|value| (key, value)).ok_or_else(|| {
            FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!(
                    "Secret '{secret_name}' in namespace '{namespace}' does not contain key '{key}'"
                ),
                hint: "Check the Secret data key in the fnox reference".to_string(),
                url: PROVIDER_URL.to_string(),
            }
        })?,
        None if data.len() == 1 => data
            .iter()
            .next()
            .map(|(key, value)| (key.as_str(), value))
            .expect("a Secret with one data entry has a first entry"),
        None => {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!(
                    "Secret '{secret_name}' in namespace '{namespace}' has {} data keys; select one explicitly",
                    data.len()
                ),
                hint: "Use secret/key or namespace/secret/key in the fnox secret value".to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }
    };

    String::from_utf8(value.0.clone()).map_err(|_| FnoxError::ProviderInvalidResponse {
        provider: PROVIDER_NAME.to_string(),
        details: format!(
            "Secret '{secret_name}' in namespace '{namespace}' key '{key}' is not valid UTF-8"
        ),
        hint: "fnox resolves text values only; choose a UTF-8 Secret data key".to_string(),
        url: PROVIDER_URL.to_string(),
    })
}

fn no_secret_data_error(namespace: &str, secret_name: &str) -> FnoxError {
    FnoxError::ProviderInvalidResponse {
        provider: PROVIDER_NAME.to_string(),
        details: format!("Secret '{secret_name}' in namespace '{namespace}' has no data"),
        hint: "Select a text key from a Secret that contains data".to_string(),
        url: PROVIDER_URL.to_string(),
    }
}

fn config_error() -> FnoxError {
    FnoxError::ProviderApiError {
        provider: PROVIDER_NAME.to_string(),
        details: "Unable to load Kubernetes client configuration".to_string(),
        hint: "Check the configured kubeconfig/context, or run where in-cluster service account authentication is available".to_string(),
        url: PROVIDER_URL.to_string(),
    }
}

fn invalid_reference(details: &str) -> FnoxError {
    FnoxError::ProviderInvalidResponse {
        provider: PROVIDER_NAME.to_string(),
        details: details.to_string(),
        hint: "Kubernetes references use secret, secret/key, or namespace/secret/key".to_string(),
        url: PROVIDER_URL.to_string(),
    }
}

fn kubernetes_error(error: kube::Error, namespace: &str, secret_name: &str) -> FnoxError {
    match error {
        kube::Error::Api(response) if response.code == 404 => FnoxError::ProviderSecretNotFound {
            provider: PROVIDER_NAME.to_string(),
            secret: format!("{namespace}/{secret_name}"),
            hint: "Check the Secret name, namespace, and configured prefix".to_string(),
            url: PROVIDER_URL.to_string(),
        },
        kube::Error::Api(response) if response.code == 401 || response.code == 403 => {
            FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details: format!(
                    "Kubernetes API denied get access to Secret '{secret_name}' in namespace '{namespace}'"
                ),
                hint: "Grant only the get verb on the required named core/v1 Secrets, and check the selected kubeconfig/context".to_string(),
                url: PROVIDER_URL.to_string(),
            }
        }
        _ => FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details: format!(
                "Unable to read Secret '{secret_name}' in namespace '{namespace}' from the Kubernetes API"
            ),
            hint: "Check Kubernetes API reachability and the selected kubeconfig/context".to_string(),
            url: PROVIDER_URL.to_string(),
        },
    }
}

fn copy_error(error: &FnoxError) -> FnoxError {
    match error {
        FnoxError::ProviderAuthFailed {
            provider,
            details,
            hint,
            url,
        } => FnoxError::ProviderAuthFailed {
            provider: provider.clone(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderSecretNotFound {
            provider,
            secret,
            hint,
            url,
        } => FnoxError::ProviderSecretNotFound {
            provider: provider.clone(),
            secret: secret.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderInvalidResponse {
            provider,
            details,
            hint,
            url,
        } => FnoxError::ProviderInvalidResponse {
            provider: provider.clone(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        FnoxError::ProviderApiError {
            provider,
            details,
            hint,
            url,
        } => FnoxError::ProviderApiError {
            provider: provider.clone(),
            details: details.clone(),
            hint: hint.clone(),
            url: url.clone(),
        },
        _ => FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details: "Unable to read the Kubernetes Secret".to_string(),
            hint: "Check the Kubernetes provider configuration".to_string(),
            url: PROVIDER_URL.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::{Path, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::get,
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Default)]
    struct TestState {
        paths: Arc<Mutex<Vec<String>>>,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    async fn get_test_secret(
        State(state): State<TestState>,
        Path((namespace, name)): Path<(String, String)>,
    ) -> Response {
        state
            .paths
            .lock()
            .unwrap()
            .push(format!("{namespace}/{name}"));
        if namespace == "concurrent" {
            let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
            state.peak.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            state.active.fetch_sub(1, Ordering::SeqCst);
        }
        match (namespace.as_str(), name.as_str()) {
            ("denied", _) => (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "code": 403,
                    "message": "never-log-this-secret-value"
                })),
            )
                .into_response(),
            ("missing", _) => (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "code": 404,
                    "message": "never-log-this-missing-secret-value"
                })),
            )
                .into_response(),
            ("binary", _) => axum::Json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "data": { "token": "/w==" }
            }))
            .into_response(),
            _ => axum::Json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "data": { "username": "YWxpY2U=", "password": "c2VjcmV0" }
            }))
            .into_response(),
        }
    }

    async fn test_client() -> (Client, TestState) {
        let state = TestState::default();
        let app = Router::new()
            .route(
                "/api/v1/namespaces/{namespace}/secrets/{name}",
                get(get_test_secret),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = Config::new(format!("http://{address}").parse().unwrap());
        (Client::try_from(config).unwrap(), state)
    }

    #[tokio::test]
    async fn distinct_secrets_are_fetched_with_bounded_concurrency() {
        let (client, state) = test_client().await;
        let provider = KubernetesProvider::new(None, None, None, None).unwrap();
        let secrets = (0..25)
            .map(|i| {
                (
                    format!("VALUE_{i}"),
                    format!("concurrent/secret-{i}/username"),
                )
            })
            .collect::<Vec<_>>();
        let results = provider
            .resolve_batch_with_client(client, "default".into(), &secrets)
            .await;
        assert_eq!(results.len(), secrets.len());
        assert!(
            results
                .values()
                .all(|result| matches!(result.as_deref(), Ok("alice")))
        );
        assert_eq!(state.paths.lock().unwrap().len(), secrets.len());
        let peak = state.peak.load(Ordering::SeqCst);
        assert!(peak > 1, "Secret requests must overlap");
        assert!(
            peak <= 10,
            "Secret requests must respect the concurrency limit"
        );
    }

    #[test]
    fn context_and_namespace_precedence_are_explicit() {
        assert_eq!(
            selected_context(Some("configured"), Some("environment")),
            Some("configured".to_string())
        );
        assert_eq!(
            selected_context(None, Some("environment")),
            Some("environment".to_string())
        );
        assert_eq!(selected_context(None, None), None);

        let provider = KubernetesProvider::new(
            None,
            Some("configured-namespace".to_string()),
            None,
            Some("prefix-".to_string()),
        )
        .unwrap();
        assert_eq!(provider.secret_name("database"), "prefix-database");
        let reference = parse_reference("override/database/password").unwrap();
        assert_eq!(reference.namespace.as_deref(), Some("override"));
        assert_eq!(reference.name, "database");
        assert_eq!(reference.key.as_deref(), Some("password"));
    }

    #[tokio::test]
    async fn explicit_kubeconfig_context_and_namespace_have_documented_precedence() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"
apiVersion: v1
kind: Config
clusters:
  - name: first
    cluster:
      server: http://127.0.0.1:12345
contexts:
  - name: current
    context:
      cluster: first
      namespace: current-namespace
  - name: selected
    context:
      cluster: first
      namespace: selected-namespace
current-context: current
users: []
"#,
        )
        .unwrap();
        let kubeconfig = Some(file.path().to_string_lossy().into_owned());

        let provider =
            KubernetesProvider::new(Some("selected".to_string()), None, kubeconfig.clone(), None)
                .unwrap();
        let (_, namespace) = provider.client_and_namespace().await.unwrap();
        assert_eq!(namespace, "selected-namespace");

        let provider = KubernetesProvider::new(
            Some("selected".to_string()),
            Some("configured-namespace".to_string()),
            kubeconfig,
            None,
        )
        .unwrap();
        let (_, namespace) = provider.client_and_namespace().await.unwrap();
        assert_eq!(namespace, "configured-namespace");
    }

    #[test]
    fn rejects_ambiguous_or_empty_references() {
        for reference in ["", "/secret", "secret/", "a/b/c/d"] {
            assert!(parse_reference(reference).is_err(), "{reference}");
        }
    }

    #[test]
    fn non_empty_kubeconfig_environment_is_explicit() {
        assert!(has_non_empty_value(Some("/tmp/kubeconfig")));
        assert!(!has_non_empty_value(Some("  ")));
        assert!(!has_non_empty_value(None));
    }

    #[test]
    fn short_references_require_exactly_one_non_empty_data_key() {
        let single = secret_with_data(Some(&[("token", "value")]));
        assert_eq!(
            read_secret_value(&single, "team", "single", None).unwrap(),
            "value"
        );

        for (name, secret) in [
            (
                "multiple",
                secret_with_data(Some(&[("username", "alice"), ("password", "secret")])),
            ),
            ("empty", secret_with_data(Some(&[]))),
            ("absent", secret_with_data(None)),
        ] {
            let error = read_secret_value(&secret, "team", name, None).unwrap_err();
            assert!(matches!(error, FnoxError::ProviderInvalidResponse { .. }));
            if matches!(name, "empty" | "absent") {
                assert!(error.to_string().contains("has no data"));
            }
        }
    }

    #[tokio::test]
    async fn batches_named_gets_without_list_or_watch_and_deduplicates_targets() {
        let (client, state) = test_client().await;
        let provider = KubernetesProvider::new(
            None,
            Some("configured".to_string()),
            None,
            Some("prefix-".to_string()),
        )
        .unwrap();
        let results = provider
            .resolve_batch_with_client(
                client,
                "configured".to_string(),
                &[
                    ("USERNAME".to_string(), "team/app/username".to_string()),
                    ("PASSWORD".to_string(), "team/app/password".to_string()),
                    ("DEFAULT".to_string(), "app/username".to_string()),
                ],
            )
            .await;

        assert_eq!(results["USERNAME"].as_ref().unwrap(), "alice");
        assert_eq!(results["PASSWORD"].as_ref().unwrap(), "secret");
        assert_eq!(results["DEFAULT"].as_ref().unwrap(), "alice");
        let paths = state.paths.lock().unwrap().clone();
        assert_eq!(
            paths
                .iter()
                .filter(|path| *path == "team/prefix-app")
                .count(),
            1
        );
        assert_eq!(
            paths
                .iter()
                .filter(|path| *path == "configured/prefix-app")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn classifies_rbac_and_response_errors_without_secret_payloads() {
        let (client, _) = test_client().await;
        let provider = KubernetesProvider::new(None, None, None, None).unwrap();
        let results = provider
            .resolve_batch_with_client(
                client,
                "configured".to_string(),
                &[
                    ("DENIED".to_string(), "denied/app/token".to_string()),
                    ("MISSING".to_string(), "missing/app/token".to_string()),
                    ("BINARY".to_string(), "binary/app/token".to_string()),
                ],
            )
            .await;

        assert!(matches!(
            results["DENIED"],
            Err(FnoxError::ProviderAuthFailed { .. })
        ));
        assert!(matches!(
            results["MISSING"],
            Err(FnoxError::ProviderSecretNotFound { .. })
        ));
        let denied = results["DENIED"].as_ref().unwrap_err().to_string();
        let missing = results["MISSING"].as_ref().unwrap_err().to_string();
        assert!(!denied.contains("never-log-this-secret-value"));
        assert!(!missing.contains("never-log-this-missing-secret-value"));
        assert!(matches!(
            results["BINARY"],
            Err(FnoxError::ProviderInvalidResponse { .. })
        ));
    }

    fn secret_with_data(entries: Option<&[(&str, &str)]>) -> Secret {
        Secret {
            data: entries.map(|entries| {
                entries
                    .iter()
                    .map(|(key, value)| {
                        (
                            (*key).to_string(),
                            k8s_openapi::ByteString(value.as_bytes().to_vec()),
                        )
                    })
                    .collect()
            }),
            ..Secret::default()
        }
    }
}
