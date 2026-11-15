use crate::env;
use crate::error::{FnoxError, Result};
use azure_core::credentials::TokenCredential;
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId, WorkloadIdentityCredential,
    WorkloadIdentityCredentialOptions,
};
use std::sync::Arc;

/// The service principal and workload identity variables [`build_credential`]
/// reads in the default mode.
pub const SERVICE_PRINCIPAL_ENV_VARS: &[&str] = &[
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_FEDERATED_TOKEN_FILE",
];

/// How an Azure provider authenticates, from its `auth` and
/// `managed_identity_client_id` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AzureAuth {
    /// A service principal from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
    /// `AZURE_CLIENT_SECRET` when all three are set, then workload identity
    /// from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_FEDERATED_TOKEN_FILE`
    /// when all three are set, otherwise the Azure CLI or Azure Developer CLI
    /// login.
    Default,
    /// The managed identity of the Azure host. `client_id` selects a
    /// user-assigned identity; without it the system-assigned identity is used.
    ManagedIdentity { client_id: Option<String> },
}

impl AzureAuth {
    pub fn from_config(
        auth: Option<&str>,
        managed_identity_client_id: Option<String>,
    ) -> Result<Self> {
        let client_id = managed_identity_client_id.filter(|id| !id.is_empty());
        match auth.filter(|a| !a.is_empty()) {
            None | Some("default") => {
                if client_id.is_some() {
                    return Err(FnoxError::Config(
                        "managed_identity_client_id requires auth = \"managed-identity\""
                            .to_string(),
                    ));
                }
                Ok(Self::Default)
            }
            Some("managed-identity") => Ok(Self::ManagedIdentity { client_id }),
            Some(other) => Err(FnoxError::Config(format!(
                "unknown Azure auth '{other}' - expected \"default\" or \"managed-identity\""
            ))),
        }
    }

    /// What to tell the user when authentication fails.
    pub fn hint(&self) -> &'static str {
        match self {
            Self::Default => {
                "Run 'az login', or set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (or AZURE_FEDERATED_TOKEN_FILE for workload identity)"
            }
            Self::ManagedIdentity { .. } => {
                "Check that this host has a managed identity with access to the resource"
            }
        }
    }

    /// Build the credential for this mode.
    pub fn build_credential(&self, provider: &str, url: &str) -> Result<Arc<dyn TokenCredential>> {
        let auth_failed = |e: azure_core::Error| FnoxError::ProviderAuthFailed {
            provider: provider.to_string(),
            details: e.to_string(),
            hint: self.hint().to_string(),
            url: url.to_string(),
        };

        match self {
            Self::ManagedIdentity { client_id } => {
                tracing::debug!("{provider}: using managed identity credential");
                let options = ManagedIdentityCredentialOptions {
                    user_assigned_id: client_id.clone().map(UserAssignedId::ClientId),
                    ..Default::default()
                };
                Ok(ManagedIdentityCredential::new(Some(options)).map_err(auth_failed)?)
            }
            Self::Default => match default_source() {
                DefaultSource::ServicePrincipal([tenant_id, client_id, client_secret]) => {
                    tracing::debug!("{provider}: using service principal from AZURE_CLIENT_ID");
                    Ok(ClientSecretCredential::new(
                        &tenant_id,
                        client_id,
                        client_secret.into(),
                        None,
                    )
                    .map_err(auth_failed)?)
                }
                DefaultSource::WorkloadIdentity([tenant_id, client_id, token_file]) => {
                    tracing::debug!(
                        "{provider}: using workload identity from AZURE_FEDERATED_TOKEN_FILE"
                    );
                    Ok(
                        workload_identity_credential(tenant_id, client_id, token_file)
                            .map_err(auth_failed)?,
                    )
                }
                DefaultSource::Cli => {
                    tracing::debug!("{provider}: using Azure CLI / Azure Developer CLI credential");
                    Ok(DeveloperToolsCredential::new(None).map_err(auth_failed)?)
                }
            },
        }
    }
}

fn workload_identity_credential(
    tenant_id: String,
    client_id: String,
    token_file: String,
) -> azure_core::Result<Arc<WorkloadIdentityCredential>> {
    WorkloadIdentityCredential::new(Some(WorkloadIdentityCredentialOptions {
        tenant_id: Some(tenant_id),
        client_id: Some(client_id),
        token_file_path: Some(token_file.into()),
        ..Default::default()
    }))
}

/// Which credential the default mode signs in with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultSource {
    ServicePrincipal([String; 3]),
    WorkloadIdentity([String; 3]),
    Cli,
}

/// Pick the default-mode credential from `get`, in order: service principal,
/// workload identity, then the CLI. Unset and empty variables count as missing.
pub fn default_source_from(get: impl Fn(&str) -> Option<String>) -> DefaultSource {
    let get = |name: &str| get(name).filter(|v| !v.is_empty());
    let triple = |third: &str| {
        Some([
            get("AZURE_TENANT_ID")?,
            get("AZURE_CLIENT_ID")?,
            get(third)?,
        ])
    };
    if let Some(sp) = triple("AZURE_CLIENT_SECRET") {
        DefaultSource::ServicePrincipal(sp)
    } else if let Some(wi) = triple("AZURE_FEDERATED_TOKEN_FILE") {
        DefaultSource::WorkloadIdentity(wi)
    } else {
        DefaultSource::Cli
    }
}

fn default_source() -> DefaultSource {
    default_source_from(|name| env::var(name).ok())
}

/// Whether the environment alone provides a credential, so no CLI login is needed.
pub fn has_env_credentials() -> bool {
    default_source() != DefaultSource::Cli
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(vars: &[(&str, &str)]) -> DefaultSource {
        let map: std::collections::HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        default_source_from(|name| map.get(name).cloned())
    }

    fn triple(a: &str, b: &str, c: &str) -> [String; 3] {
        [a.to_string(), b.to_string(), c.to_string()]
    }

    #[test]
    fn test_default_mode_tracks_workload_identity_vars() {
        assert!(SERVICE_PRINCIPAL_ENV_VARS.contains(&"AZURE_FEDERATED_TOKEN_FILE"));
    }

    #[test]
    fn test_default_source_workload_identity() {
        assert_eq!(
            source(&[
                ("AZURE_TENANT_ID", "t"),
                ("AZURE_CLIENT_ID", "c"),
                ("AZURE_FEDERATED_TOKEN_FILE", "/tok"),
            ]),
            DefaultSource::WorkloadIdentity(triple("t", "c", "/tok"))
        );
    }

    #[test]
    fn test_default_source_service_principal_wins() {
        assert_eq!(
            source(&[
                ("AZURE_TENANT_ID", "t"),
                ("AZURE_CLIENT_ID", "c"),
                ("AZURE_CLIENT_SECRET", "s"),
                ("AZURE_FEDERATED_TOKEN_FILE", "/tok"),
            ]),
            DefaultSource::ServicePrincipal(triple("t", "c", "s"))
        );
    }

    #[test]
    fn test_default_source_incomplete_or_empty_falls_back_to_cli() {
        assert_eq!(source(&[]), DefaultSource::Cli);
        // Missing tenant, missing client, missing token file.
        assert_eq!(
            source(&[
                ("AZURE_CLIENT_ID", "c"),
                ("AZURE_FEDERATED_TOKEN_FILE", "/tok")
            ]),
            DefaultSource::Cli
        );
        assert_eq!(
            source(&[
                ("AZURE_TENANT_ID", "t"),
                ("AZURE_FEDERATED_TOKEN_FILE", "/tok")
            ]),
            DefaultSource::Cli
        );
        assert_eq!(
            source(&[("AZURE_TENANT_ID", "t"), ("AZURE_CLIENT_ID", "c")]),
            DefaultSource::Cli
        );
        // Empty token file counts as unset.
        assert_eq!(
            source(&[
                ("AZURE_TENANT_ID", "t"),
                ("AZURE_CLIENT_ID", "c"),
                ("AZURE_FEDERATED_TOKEN_FILE", ""),
            ]),
            DefaultSource::Cli
        );
    }

    #[test]
    fn test_workload_identity_credential_reads_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "jwt").unwrap();
        assert!(
            workload_identity_credential("t".into(), "c".into(), file.display().to_string())
                .is_ok()
        );
        // A missing token file is reported when the credential is built.
        let missing = dir.path().join("missing");
        assert!(
            workload_identity_credential("t".into(), "c".into(), missing.display().to_string())
                .is_err()
        );
    }

    #[test]
    fn test_from_config_default() {
        assert_eq!(
            AzureAuth::from_config(None, None).unwrap(),
            AzureAuth::Default
        );
        assert_eq!(
            AzureAuth::from_config(Some("default"), None).unwrap(),
            AzureAuth::Default
        );
        assert_eq!(
            AzureAuth::from_config(Some(""), Some(String::new())).unwrap(),
            AzureAuth::Default
        );
    }

    #[test]
    fn test_from_config_managed_identity() {
        assert_eq!(
            AzureAuth::from_config(Some("managed-identity"), None).unwrap(),
            AzureAuth::ManagedIdentity { client_id: None }
        );
        assert_eq!(
            AzureAuth::from_config(Some("managed-identity"), Some("abc".to_string())).unwrap(),
            AzureAuth::ManagedIdentity {
                client_id: Some("abc".to_string())
            }
        );
    }

    #[test]
    fn test_from_config_rejects_invalid() {
        assert!(AzureAuth::from_config(Some("cli"), None).is_err());
        assert!(AzureAuth::from_config(None, Some("abc".to_string())).is_err());
    }
}
