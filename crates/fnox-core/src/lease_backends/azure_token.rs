use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use crate::providers::azure_shared::{self, AzureAuth};
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use indexmap::IndexMap;
use std::sync::Arc;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/azure-token";

/// All env var names the Azure Token backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = azure_shared::SERVICE_PRINCIPAL_ENV_VARS;

pub fn check_prerequisites(
    auth: Option<&str>,
    managed_identity_client_id: &Option<String>,
) -> Option<String> {
    match AzureAuth::from_config(auth, managed_identity_client_id.clone()) {
        // Managed identity never needs `az` or a service principal.
        Ok(AzureAuth::ManagedIdentity { .. }) => return None,
        // Invalid settings are reported when the backend is created.
        Err(_) => return None,
        Ok(AzureAuth::Default) => {}
    }
    if azure_shared::service_principal_env().is_some() {
        return None;
    }
    let has_az = which::which("az").is_ok();
    if has_az {
        None
    } else {
        Some("Azure credentials not found. Run 'az login' or set AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID.".to_string())
    }
}

/// Env vars the backend may consume; managed identity reads none of them.
pub fn consumed_env_vars(auth: Option<&str>) -> &'static [&'static str] {
    if auth == Some("managed-identity") {
        &[]
    } else {
        CONSUMED_ENV_VARS
    }
}

pub fn required_env_vars(auth: Option<&str>) -> Vec<(&'static str, &'static str)> {
    if auth == Some("managed-identity") {
        return Vec::new();
    }
    vec![
        ("AZURE_CLIENT_ID", "Azure application (client) ID"),
        ("AZURE_CLIENT_SECRET", "Azure client secret"),
        ("AZURE_TENANT_ID", "Azure tenant (directory) ID"),
    ]
}

pub struct AzureTokenBackend {
    scope: String,
    env_var: String,
    auth: AzureAuth,
}

impl AzureTokenBackend {
    pub fn new(
        scope: String,
        env_var: String,
        auth: Option<&str>,
        managed_identity_client_id: Option<String>,
    ) -> Result<Self> {
        // An empty ID would silently select the system-assigned identity.
        if managed_identity_client_id.as_deref() == Some("") {
            return Err(FnoxError::Config(
                "managed_identity_client_id must not be empty; omit it to use the system-assigned identity"
                    .to_string(),
            ));
        }
        Ok(Self {
            scope,
            env_var,
            auth: AzureAuth::from_config(auth, managed_identity_client_id)?,
        })
    }

    fn failure_hint(&self) -> String {
        let identity = match &self.auth {
            AzureAuth::ManagedIdentity {
                client_id: Some(id),
            } => format!(" (user-assigned identity {id})"),
            _ => String::new(),
        };
        format!(
            "Failed to acquire Azure token. {}{identity}, and check the scope.",
            self.auth.hint()
        )
    }

    fn build_credential(&self) -> Result<Arc<dyn TokenCredential>> {
        self.auth.build_credential("Azure Token", URL)
    }
}

#[async_trait]
impl LeaseBackend for AzureTokenBackend {
    async fn create_lease(&self, duration: Duration, _label: &str) -> Result<Lease> {
        if duration < Duration::from_secs(3600) {
            tracing::warn!(
                "Azure controls token lifetime (~1h); requested duration {}m will be ignored",
                duration.as_secs() / 60
            );
        }
        let credential = self.build_credential()?;

        let token_response =
            credential
                .get_token(&[&self.scope], None)
                .await
                .map_err(|e: azure_core::Error| FnoxError::ProviderAuthFailed {
                    provider: "Azure Token".to_string(),
                    details: e.to_string(),
                    hint: self.failure_hint(),
                    url: URL.to_string(),
                })?;

        let expires_at =
            chrono::DateTime::from_timestamp(token_response.expires_on.unix_timestamp(), 0)
                .or_else(|| {
                    tracing::warn!("Azure token returned an out-of-range expiration timestamp");
                    None
                });

        let mut credentials = IndexMap::new();
        credentials.insert(
            self.env_var.clone(),
            token_response.token.secret().to_string(),
        );

        let lease_id = super::generate_lease_id("azure-token");

        Ok(Lease {
            credentials,
            expires_at,
            lease_id,
        })
    }

    fn max_lease_duration(&self) -> Duration {
        // Azure controls token lifetime (~1 hour), not configurable by caller
        Duration::from_secs(3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_identity_skips_prerequisites() {
        assert!(check_prerequisites(Some("managed-identity"), &None).is_none());
    }

    #[test]
    fn managed_identity_needs_no_service_principal_env() {
        assert!(required_env_vars(Some("managed-identity")).is_empty());
        assert!(consumed_env_vars(Some("managed-identity")).is_empty());
        assert_eq!(required_env_vars(None).len(), 3);
        assert_eq!(consumed_env_vars(None), CONSUMED_ENV_VARS);
    }

    #[test]
    fn failure_hint_names_user_assigned_identity() {
        let backend = AzureTokenBackend::new(
            "s".into(),
            "T".into(),
            Some("managed-identity"),
            Some("abc-123".into()),
        )
        .unwrap();
        assert!(
            backend
                .failure_hint()
                .contains("user-assigned identity abc-123")
        );
        let system =
            AzureTokenBackend::new("s".into(), "T".into(), Some("managed-identity"), None).unwrap();
        assert!(!system.failure_hint().contains("user-assigned"));
    }

    #[test]
    fn rejects_empty_client_id() {
        assert!(
            AzureTokenBackend::new(
                "s".into(),
                "T".into(),
                Some("managed-identity"),
                Some(String::new())
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_client_id_without_managed_identity() {
        assert!(AzureTokenBackend::new("s".into(), "T".into(), None, Some("abc".into())).is_err());
        assert!(
            AzureTokenBackend::new("s".into(), "T".into(), Some("managed-identity"), None).is_ok()
        );
    }
}
