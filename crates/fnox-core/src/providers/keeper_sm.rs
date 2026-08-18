use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use keeper_secrets_manager_core::{
    ClientOptions, FileKeyValueStorage, InMemoryKeyValueStorage, KSMRError, SecretsManager,
};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

const PROVIDER_NAME: &str = "Keeper Secrets Manager";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/keeper-sm";
const BATCH_CONCURRENCY: usize = 10;

pub fn env_dependencies() -> &'static [&'static str] {
    &[
        "FNOX_KEEPER_CONFIG",
        "KSM_CONFIG",
        "FNOX_KEEPER_TOKEN",
        "KSM_TOKEN",
    ]
}

enum KeeperStorage {
    File(String),
    InMemory(String),
}

pub struct KeeperSecretsManagerProvider {
    manager: Arc<Mutex<SecretsManager>>,
    parallel_ready: Arc<AtomicBool>,
}

impl KeeperSecretsManagerProvider {
    pub fn new(config_file: Option<String>, token: Option<String>) -> Result<Self> {
        let token = token.or_else(keeper_token);
        let requires_bootstrap = token.is_some();
        let storage = resolve_storage(config_file);

        validate_bootstrap_storage(&storage, token.is_some())?;

        if let KeeperStorage::File(path) = &storage
            && token.is_none()
            && !std::path::Path::new(path).exists()
        {
            return Err(FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Configuration file '{}' does not exist", path),
                hint: "Download a KSM configuration file, set KSM_CONFIG, or provide a one-time KSM_TOKEN for bootstrap"
                    .to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }

        // The Keeper SDK constructs a reqwest blocking client. Do that outside the
        // Tokio runtime so reqwest does not attempt to create a nested runtime.
        let manager = std::thread::spawn(move || create_manager(storage, token))
            .join()
            .map_err(|_| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: "Keeper SDK initialization thread panicked".to_string(),
                hint: "Check the Keeper configuration and retry".to_string(),
                url: PROVIDER_URL.to_string(),
            })??;

        Ok(Self {
            manager: Arc::new(Mutex::new(manager)),
            parallel_ready: Arc::new(AtomicBool::new(!requires_bootstrap)),
        })
    }

    async fn run_blocking<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut SecretsManager) -> Result<T> + Send + 'static,
    {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut manager = manager.lock().map_err(|_| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: "Keeper SDK client lock was poisoned".to_string(),
                hint: "Retry the command".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;
            operation(&mut manager)
        })
        .await
        .map_err(|e| FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details: format!("Keeper SDK task failed: {e}"),
            hint: "Retry the command".to_string(),
            url: PROVIDER_URL.to_string(),
        })?
    }

    async fn run_cloned<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut SecretsManager) -> Result<T> + Send + 'static,
    {
        let mut manager = self
            .manager
            .lock()
            .map_err(|_| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: "Keeper SDK client lock was poisoned".to_string(),
                hint: "Retry the command".to_string(),
                url: PROVIDER_URL.to_string(),
            })?
            .clone();

        tokio::task::spawn_blocking(move || operation(&mut manager))
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Keeper SDK task failed: {e}"),
                hint: "Retry the command".to_string(),
                url: PROVIDER_URL.to_string(),
            })?
    }

    async fn ensure_parallel_ready(&self) -> Result<()> {
        if self.parallel_ready.load(Ordering::Acquire) {
            return Ok(());
        }

        let parallel_ready = Arc::clone(&self.parallel_ready);
        self.run_blocking(move |manager| {
            if parallel_ready.load(Ordering::Acquire) {
                return Ok(());
            }

            // Redeem a one-time token on the shared client before cloning it for
            // concurrent requests. Cloning an unbound client could redeem the same
            // token more than once.
            manager
                .get_secrets(Vec::new())
                .map_err(|e| map_ksm_error(e, None))?;
            parallel_ready.store(true, Ordering::Release);
            Ok(())
        })
        .await
    }
}

fn validate_bootstrap_storage(storage: &KeeperStorage, has_token: bool) -> Result<()> {
    if matches!(storage, KeeperStorage::InMemory(_)) && has_token {
        return Err(FnoxError::Config(
            "Keeper one-time token bootstrap requires config_file so the bound client configuration can be persisted"
                .to_string(),
        ));
    }
    Ok(())
}

fn resolve_storage(config_file: Option<String>) -> KeeperStorage {
    if let Some(path) = config_file {
        let path = crate::config_path::resolve_string_relative_to_file(path, None);
        return KeeperStorage::File(path);
    }

    if let Some(config) = keeper_config() {
        return KeeperStorage::InMemory(config);
    }

    KeeperStorage::File(
        env::HOME_DIR
            .join(".keeper")
            .join("ksm-config.json")
            .to_string_lossy()
            .into_owned(),
    )
}

fn create_manager(storage: KeeperStorage, token: Option<String>) -> Result<SecretsManager> {
    let storage = match storage {
        KeeperStorage::File(path) => FileKeyValueStorage::new_config_storage(path),
        KeeperStorage::InMemory(config) => {
            InMemoryKeyValueStorage::new_config_storage(Some(config))
        }
    }
    .map_err(|e| map_ksm_error(e, None))?;

    let options = match token {
        Some(token) => ClientOptions::new_client_options_with_token(token, storage),
        None => ClientOptions::new_client_options(storage),
    };

    SecretsManager::new(options).map_err(|e| map_ksm_error(e, None))
}

fn keeper_config() -> Option<String> {
    env::var("FNOX_KEEPER_CONFIG")
        .or_else(|_| env::var("KSM_CONFIG"))
        .ok()
        .filter(|value| !value.is_empty())
}

fn keeper_token() -> Option<String> {
    env::var("FNOX_KEEPER_TOKEN")
        .or_else(|_| env::var("KSM_TOKEN"))
        .ok()
        .filter(|value| !value.is_empty())
}

fn notation_value_to_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value,
        value => value.to_string(),
    }
}

fn map_ksm_error(error: KSMRError, secret: Option<&str>) -> FnoxError {
    let details = error.to_string();
    match error {
        KSMRError::AuthenticationError(_)
        | KSMRError::InvalidTokenError(_)
        | KSMRError::ConfigurationError(_)
        | KSMRError::SecretManagerCreationError(_)
        | KSMRError::KeyNotFoundError(_) => FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details,
            hint: "Check the Keeper client configuration or one-time token".to_string(),
            url: PROVIDER_URL.to_string(),
        },
        KSMRError::RecordNotFoundError(_)
        | KSMRError::FieldNotFoundError(_)
        | KSMRError::NotationError(_)
            if secret.is_some() && details.to_lowercase().contains("no record") =>
        {
            FnoxError::ProviderSecretNotFound {
                provider: PROVIDER_NAME.to_string(),
                secret: secret.unwrap_or_default().to_string(),
                hint: "Check that the Keeper notation references an accessible record and field"
                    .to_string(),
                url: PROVIDER_URL.to_string(),
            }
        }
        KSMRError::RecordNotFoundError(_) | KSMRError::FieldNotFoundError(_) => {
            FnoxError::ProviderSecretNotFound {
                provider: PROVIDER_NAME.to_string(),
                secret: secret.unwrap_or_default().to_string(),
                hint: "Check that the Keeper notation references an accessible record and field"
                    .to_string(),
                url: PROVIDER_URL.to_string(),
            }
        }
        KSMRError::NotationError(_) => FnoxError::ProviderInvalidResponse {
            provider: PROVIDER_NAME.to_string(),
            details,
            hint: "Use Keeper notation such as RECORD_UID/field/password".to_string(),
            url: PROVIDER_URL.to_string(),
        },
        _ => FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details,
            hint: "Check network access and the Keeper Secrets Manager configuration".to_string(),
            url: PROVIDER_URL.to_string(),
        },
    }
}

#[async_trait]
impl crate::providers::Provider for KeeperSecretsManagerProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteRead]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let notation = value.to_string();
        tracing::debug!(notation = %notation, "Getting secret from Keeper Secrets Manager");
        self.run_blocking(move |manager| {
            manager
                .get_notation(&notation)
                .map(notation_value_to_string)
                .map_err(|e| map_ksm_error(e, Some(&notation)))
        })
        .await
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        use futures::stream::{self, StreamExt};

        if secrets.is_empty() {
            return HashMap::new();
        }

        if let Err(error) = self.ensure_parallel_ready().await {
            return secrets
                .iter()
                .map(|(key, _)| {
                    (
                        key.clone(),
                        Err(FnoxError::ProviderApiError {
                            provider: PROVIDER_NAME.to_string(),
                            details: error.to_string(),
                            hint: "Retry the command".to_string(),
                            url: PROVIDER_URL.to_string(),
                        }),
                    )
                })
                .collect();
        }

        stream::iter(secrets.to_vec())
            .map(|(key, notation)| async move {
                let requested_notation = notation.clone();
                let result = self
                    .run_cloned(move |manager| {
                        manager
                            .get_notation(&requested_notation)
                            .map(notation_value_to_string)
                            .map_err(|e| map_ksm_error(e, Some(&requested_notation)))
                    })
                    .await;
                (key, result)
            })
            .buffer_unordered(BATCH_CONCURRENCY)
            .collect()
            .await
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Keeper Secrets Manager");
        self.run_blocking(|manager| {
            manager
                .get_secrets(Vec::new())
                .map(|_| ())
                .map_err(|e| map_ksm_error(e, None))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_keeper_notation_values_to_strings() {
        assert_eq!(
            notation_value_to_string(serde_json::json!("secret")),
            "secret"
        );
        assert_eq!(notation_value_to_string(serde_json::json!(42)), "42");
        assert_eq!(
            notation_value_to_string(serde_json::json!({"host": "db"})),
            r#"{"host":"db"}"#
        );
    }

    #[test]
    fn maps_authentication_errors() {
        let error = map_ksm_error(KSMRError::AuthenticationError("denied".to_string()), None);
        assert!(matches!(error, FnoxError::ProviderAuthFailed { .. }));
    }

    #[test]
    fn maps_missing_records() {
        let error = map_ksm_error(
            KSMRError::NotationError("No records matched abc".to_string()),
            Some("abc/field/password"),
        );
        assert!(matches!(error, FnoxError::ProviderSecretNotFound { .. }));
    }

    #[test]
    fn rejects_bootstrap_with_in_memory_storage() {
        let storage = KeeperStorage::InMemory("e30=".to_string());
        assert!(validate_bootstrap_storage(&storage, true).is_err());
        assert!(validate_bootstrap_storage(&storage, false).is_ok());
    }

    #[tokio::test]
    async fn initializes_sdk_client_from_a_tokio_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let config_file = temp.path().join("ksm-config.json");
        let token = "US:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let result = KeeperSecretsManagerProvider::new(
            Some(config_file.to_string_lossy().into_owned()),
            Some(token.to_string()),
        );

        if let Err(error) = result {
            panic!("Keeper SDK initialization failed: {error}");
        }
    }
}
