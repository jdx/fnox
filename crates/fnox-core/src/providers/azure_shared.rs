//! Azure sign-in settings shared by the Azure providers, the `azure-token`
//! lease backend and the `azure-container-apps` push target. Parsing the
//! settings needs no Azure SDK, so it is compiled into every build; building a
//! credential needs the `azure` feature.

use crate::env;
use crate::error::{FnoxError, Result};
#[cfg(feature = "azure")]
use azure_core::credentials::TokenCredential;
#[cfg(feature = "azure")]
use azure_core::credentials::{AccessToken, TokenRequestOptions};
#[cfg(feature = "azure")]
use azure_identity::{
    AzureCliCredential, AzureCliCredentialOptions, AzureDeveloperCliCredential,
    AzureDeveloperCliCredentialOptions, ClientSecretCredential, DeveloperToolsCredential,
    ManagedIdentityCredential, ManagedIdentityCredentialOptions, UserAssignedId,
    WorkloadIdentityCredential, WorkloadIdentityCredentialOptions,
};
#[cfg(feature = "azure")]
use std::sync::Arc;
#[cfg(feature = "azure")]
use std::sync::OnceLock;

/// The service principal and workload identity variables [`build_credential`]
/// reads in the default mode.
pub const SERVICE_PRINCIPAL_ENV_VARS: &[&str] = &[
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_FEDERATED_TOKEN_FILE",
];

/// How an Azure provider authenticates, from its `auth`,
/// `managed_identity_client_id` and `tenant_id` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AzureAuth {
    /// A service principal from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
    /// `AZURE_CLIENT_SECRET` when all three are set, then workload identity
    /// from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_FEDERATED_TOKEN_FILE`
    /// when all three are set, otherwise the Azure CLI or Azure Developer CLI
    /// login. `tenant_id` pins the tenant the CLI login requests tokens from,
    /// whatever subscription the CLI has selected; without it the CLI's
    /// current tenant is used.
    Default { tenant_id: Option<String> },
    /// The managed identity of the Azure host. `client_id` selects a
    /// user-assigned identity; without it the system-assigned identity is used.
    ManagedIdentity { client_id: Option<String> },
}

impl AzureAuth {
    pub fn from_config(
        auth: Option<&str>,
        managed_identity_client_id: Option<String>,
        tenant_id: Option<String>,
    ) -> Result<Self> {
        let client_id = managed_identity_client_id.filter(|id| !id.is_empty());
        let tenant_id = tenant_id.filter(|id| !id.is_empty());
        match auth.filter(|a| !a.is_empty()) {
            None | Some("default") => {
                if client_id.is_some() {
                    return Err(FnoxError::Config(
                        "managed_identity_client_id requires auth = \"managed-identity\""
                            .to_string(),
                    ));
                }
                Ok(Self::Default { tenant_id })
            }
            Some("managed-identity") => {
                if tenant_id.is_some() {
                    return Err(FnoxError::Config(
                        "tenant_id applies to the Azure CLI login and cannot be used with auth = \"managed-identity\""
                            .to_string(),
                    ));
                }
                Ok(Self::ManagedIdentity { client_id })
            }
            Some(other) => Err(FnoxError::Config(format!(
                "unknown Azure auth '{other}' - expected \"default\" or \"managed-identity\""
            ))),
        }
    }

    /// What to tell the user when authentication fails.
    pub fn hint(&self) -> String {
        match self {
            Self::Default { tenant_id: None } => {
                "Run 'az login', or set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (or AZURE_FEDERATED_TOKEN_FILE for workload identity)".to_string()
            }
            Self::Default {
                tenant_id: Some(tenant),
            } => format!(
                "Run 'az login --tenant {tenant}', or set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (or AZURE_FEDERATED_TOKEN_FILE for workload identity)"
            ),
            Self::ManagedIdentity { .. } => {
                "Check that this host has a managed identity with access to the resource"
                    .to_string()
            }
        }
    }

    /// Build the credential for this mode.
    #[cfg(feature = "azure")]
    pub fn build_credential(&self, provider: &str, url: &str) -> Result<Arc<dyn TokenCredential>> {
        let auth_failed = |e: azure_core::Error| FnoxError::ProviderAuthFailed {
            provider: provider.to_string(),
            details: e.to_string(),
            hint: self.hint(),
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
            Self::Default { tenant_id } => match default_source() {
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
                DefaultSource::Cli => match tenant_id {
                    None => {
                        tracing::debug!(
                            "{provider}: using Azure CLI / Azure Developer CLI credential"
                        );
                        Ok(DeveloperToolsCredential::new(None).map_err(auth_failed)?)
                    }
                    Some(tenant_id) => {
                        tracing::debug!(
                            "{provider}: using Azure CLI / Azure Developer CLI credential for tenant {tenant_id}"
                        );
                        Ok(cli_credential_for_tenant(tenant_id).map_err(auth_failed)?)
                    }
                },
            },
        }
    }
}

/// The Azure CLI, then the Azure Developer CLI, both requesting tokens from
/// `tenant_id`. Like `DeveloperToolsCredential`, which takes no tenant, it
/// keeps using the first tool that returns a token.
#[cfg(feature = "azure")]
fn cli_credential_for_tenant(tenant_id: &str) -> azure_core::Result<Arc<TenantCliCredential>> {
    cli_credential_for_tenant_with(tenant_id, None)
}

/// [`cli_credential_for_tenant`] with the executor that runs `az` and `azd`;
/// `None` uses the SDK's default.
#[cfg(feature = "azure")]
fn cli_credential_for_tenant_with(
    tenant_id: &str,
    executor: Option<Arc<dyn azure_identity::Executor>>,
) -> azure_core::Result<Arc<TenantCliCredential>> {
    let sources: Vec<Arc<dyn TokenCredential>> = vec![
        AzureCliCredential::new(Some(AzureCliCredentialOptions {
            tenant_id: Some(tenant_id.to_string()),
            executor: executor.clone(),
            ..Default::default()
        }))?,
        AzureDeveloperCliCredential::new(Some(AzureDeveloperCliCredentialOptions {
            tenant_id: Some(tenant_id.to_string()),
            executor,
        }))?,
    ];
    Ok(Arc::new(TenantCliCredential {
        sources,
        chosen: OnceLock::new(),
    }))
}

#[cfg(feature = "azure")]
#[derive(Debug)]
struct TenantCliCredential {
    sources: Vec<Arc<dyn TokenCredential>>,
    chosen: OnceLock<usize>,
}

#[cfg(feature = "azure")]
#[async_trait::async_trait]
impl TokenCredential for TenantCliCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        if let Some(&index) = self.chosen.get() {
            return self.sources[index].get_token(scopes, options).await;
        }
        let mut errors = Vec::new();
        for (index, source) in self.sources.iter().enumerate() {
            match source.get_token(scopes, options.clone()).await {
                Ok(token) => {
                    let _ = self.chosen.set(index);
                    return Ok(token);
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        Err(azure_core::Error::with_message(
            azure_core::error::ErrorKind::Credential,
            format!(
                "Neither the Azure CLI nor the Azure Developer CLI returned a token:\n{}",
                errors.join("\n")
            ),
        ))
    }
}

#[cfg(feature = "azure")]
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
    #[cfg(feature = "azure")]
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
            AzureAuth::from_config(None, None, None).unwrap(),
            AzureAuth::Default { tenant_id: None }
        );
        assert_eq!(
            AzureAuth::from_config(Some("default"), None, None).unwrap(),
            AzureAuth::Default { tenant_id: None }
        );
        assert_eq!(
            AzureAuth::from_config(Some(""), Some(String::new()), Some(String::new())).unwrap(),
            AzureAuth::Default { tenant_id: None }
        );
        assert_eq!(
            AzureAuth::from_config(None, None, Some("contoso.onmicrosoft.com".to_string()))
                .unwrap(),
            AzureAuth::Default {
                tenant_id: Some("contoso.onmicrosoft.com".to_string())
            }
        );
    }

    #[test]
    fn test_from_config_managed_identity() {
        assert_eq!(
            AzureAuth::from_config(Some("managed-identity"), None, None).unwrap(),
            AzureAuth::ManagedIdentity { client_id: None }
        );
        assert_eq!(
            AzureAuth::from_config(Some("managed-identity"), Some("abc".to_string()), None)
                .unwrap(),
            AzureAuth::ManagedIdentity {
                client_id: Some("abc".to_string())
            }
        );
    }

    #[test]
    fn test_from_config_rejects_invalid() {
        assert!(AzureAuth::from_config(Some("cli"), None, None).is_err());
        assert!(AzureAuth::from_config(None, Some("abc".to_string()), None).is_err());
        assert!(
            AzureAuth::from_config(Some("managed-identity"), None, Some("t".to_string())).is_err()
        );
    }

    #[test]
    fn test_hint_names_the_tenant() {
        let auth = AzureAuth::from_config(None, None, Some("my-tenant".to_string())).unwrap();
        assert!(auth.hint().contains("az login --tenant my-tenant"));
        assert!(
            !AzureAuth::Default { tenant_id: None }
                .hint()
                .contains("--tenant")
        );
    }

    #[test]
    #[cfg(feature = "azure")]
    fn test_cli_credential_for_tenant_validates_tenant() {
        assert!(cli_credential_for_tenant("00000000-0000-0000-0000-000000000000").is_ok());
        assert!(cli_credential_for_tenant("contoso.onmicrosoft.com").is_ok());
        // The tenant is passed to `az --tenant`, so the SDK rejects anything
        // that isn't a tenant ID or domain.
        assert!(cli_credential_for_tenant("bad tenant; rm").is_err());
    }

    /// Stands in for the shell that runs `az` and `azd`: records each command
    /// line and answers it as the tool named in `working` would.
    #[cfg(all(feature = "azure", unix))]
    #[derive(Debug)]
    struct FakeCli {
        working: &'static [&'static str],
        commands: std::sync::Mutex<Vec<String>>,
    }

    #[cfg(all(feature = "azure", unix))]
    #[async_trait::async_trait]
    impl azure_identity::Executor for FakeCli {
        async fn run(
            &self,
            _program: &std::ffi::OsStr,
            args: &[&std::ffi::OsStr],
        ) -> std::io::Result<std::process::Output> {
            use std::os::unix::process::ExitStatusExt;
            // The SDK runs `/bin/sh -c "cd /bin && <tool> ..."`.
            let command = args.last().unwrap().to_string_lossy().into_owned();
            self.commands.lock().unwrap().push(command.clone());
            let tool = command.split("&& ").nth(1).unwrap_or(&command);
            let tool = tool.split(' ').next().unwrap_or_default();
            let (code, stdout, stderr): (i32, &str, &str) = match (
                tool,
                self.working.contains(&tool),
            ) {
                ("az", true) => (
                    0,
                    r#"{"accessToken":"az-token","expires_on":4070908800,"tokenType":"Bearer"}"#,
                    "",
                ),
                ("azd", true) => (
                    0,
                    r#"{"token":"azd-token","expiresOn":"2099-01-01T00:00:00Z"}"#,
                    "",
                ),
                _ => (1, "", "ERROR: not logged in"),
            };
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(code << 8),
                stdout: stdout.as_bytes().to_vec(),
                stderr: stderr.as_bytes().to_vec(),
            })
        }
    }

    #[cfg(all(feature = "azure", unix))]
    async fn tenant_token(
        working: &'static [&'static str],
        requests: usize,
    ) -> (azure_core::Result<String>, Vec<String>) {
        let cli = Arc::new(FakeCli {
            working,
            commands: Default::default(),
        });
        let credential = cli_credential_for_tenant_with("my-tenant", Some(cli.clone())).unwrap();
        let mut result = Err(azure_core::Error::with_message(
            azure_core::error::ErrorKind::Other,
            "no request made",
        ));
        for _ in 0..requests {
            result = credential
                .get_token(&["https://vault.azure.net/.default"], None)
                .await
                .map(|t| t.token.secret().to_string());
        }
        let commands = cli.commands.lock().unwrap().clone();
        (result, commands)
    }

    #[cfg(all(feature = "azure", unix))]
    #[tokio::test]
    async fn test_tenant_credential_passes_tenant_to_az() {
        let (token, commands) = tenant_token(&["az", "azd"], 1).await;
        assert_eq!(token.unwrap(), "az-token");
        assert_eq!(commands.len(), 1, "{commands:?}");
        assert!(commands[0].contains("az account get-access-token"));
        assert!(commands[0].contains(" --tenant my-tenant"));
    }

    #[cfg(all(feature = "azure", unix))]
    #[tokio::test]
    async fn test_tenant_credential_falls_back_to_azd_and_keeps_it() {
        let (token, commands) = tenant_token(&["azd"], 2).await;
        assert_eq!(token.unwrap(), "azd-token");
        // az once, then azd; the second request goes straight to azd (or is
        // answered from the SDK's token cache) and never retries az.
        assert!(commands[0].contains(" --tenant my-tenant"));
        assert!(commands[1].contains("azd auth token"));
        assert!(commands[1].contains(" --tenant-id my-tenant"));
        assert_eq!(
            commands.iter().filter(|c| c.contains("az account")).count(),
            1,
            "{commands:?}"
        );
    }

    #[cfg(all(feature = "azure", unix))]
    #[tokio::test]
    async fn test_tenant_credential_reports_both_failures() {
        let (token, commands) = tenant_token(&[], 1).await;
        let error = token.unwrap_err().to_string();
        assert!(error.contains("Neither the Azure CLI"), "{error}");
        assert!(error.contains("AzureCliCredential"), "{error}");
        assert!(error.contains("AzureDeveloperCliCredential"), "{error}");
        assert_eq!(commands.len(), 2, "{commands:?}");
    }
}
