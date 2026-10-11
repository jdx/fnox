use crate::env;
use crate::error::{FnoxError, Result};
use azure_core::credentials::TokenCredential;
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId,
};
use std::sync::Arc;

/// The service principal variables [`build_credential`] reads in the default mode.
pub const SERVICE_PRINCIPAL_ENV_VARS: &[&str] =
    &["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"];

/// How an Azure provider authenticates, from its `auth` and
/// `managed_identity_client_id` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AzureAuth {
    /// A service principal from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
    /// `AZURE_CLIENT_SECRET` when all three are set, otherwise the Azure CLI
    /// or Azure Developer CLI login.
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
                "Run 'az login' or set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET"
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
            Self::Default => {
                if let Some([tenant_id, client_id, client_secret]) = service_principal_env() {
                    tracing::debug!("{provider}: using service principal from AZURE_CLIENT_ID");
                    return Ok(ClientSecretCredential::new(
                        &tenant_id,
                        client_id,
                        client_secret.into(),
                        None,
                    )
                    .map_err(auth_failed)?);
                }
                tracing::debug!("{provider}: using Azure CLI / Azure Developer CLI credential");
                Ok(DeveloperToolsCredential::new(None).map_err(auth_failed)?)
            }
        }
    }
}

/// `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`, when all are set.
pub fn service_principal_env() -> Option<[String; 3]> {
    let get = |name| env::var(name).ok().filter(|v: &String| !v.is_empty());
    Some([
        get("AZURE_TENANT_ID")?,
        get("AZURE_CLIENT_ID")?,
        get("AZURE_CLIENT_SECRET")?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

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
