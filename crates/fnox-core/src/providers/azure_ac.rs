use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;
use serde::Deserialize;

const PROVIDER_NAME: &str = "Azure App Configuration";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/azure-ac";
const SCOPE: &str = "https://appconfig.azure.com/.default";
const API_VERSION: &str = "2023-11-01";

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

#[derive(Deserialize)]
struct KeyValue {
    value: Option<String>,
}

pub struct AzureAppConfigurationProvider {
    endpoint: String,
    label: Option<String>,
    prefix: Option<String>,
}

impl AzureAppConfigurationProvider {
    pub fn new(endpoint: String, label: Option<String>, prefix: Option<String>) -> Result<Self> {
        // An empty label is a distinct label in App Configuration, not the absence of one.
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            label: label.filter(|l| !l.is_empty()),
            prefix: prefix.filter(|p| !p.is_empty()),
        })
    }

    fn get_key_name(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}{}", prefix, key),
            None => key.to_string(),
        }
    }

    /// Send an authenticated GET to the App Configuration data plane
    async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<reqwest::Response> {
        let token = self.get_token().await?;

        let response = crate::http::http_client()
            .get(format!("{}{}", self.endpoint, path))
            .query(&[("api-version", API_VERSION)])
            .query(query)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: format!("HTTP request failed: {}", e),
                hint: "Check network connectivity to the App Configuration store".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;

        let status = response.status();
        // 404 goes back to the caller, which knows what was being looked up.
        if status.is_success() || status.as_u16() == 404 {
            return Ok(response);
        }

        let body = response.text().await.unwrap_or_default();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details: format!("HTTP {}: {}", status, body),
                hint: "Grant the 'App Configuration Data Reader' role and check the store's network access rules"
                    .to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }
        Err(FnoxError::ProviderApiError {
            provider: PROVIDER_NAME.to_string(),
            details: format!("HTTP {}: {}", status, body),
            hint: "Check the store endpoint and your configuration".to_string(),
            url: PROVIDER_URL.to_string(),
        })
    }

    /// Acquire a Microsoft Entra ID token for the App Configuration data plane
    async fn get_token(&self) -> Result<String> {
        let credential = DeveloperToolsCredential::new(None).map_err(|e: azure_core::Error| {
            FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details: e.to_string(),
                hint: "Run 'az login' to authenticate with Azure".to_string(),
                url: PROVIDER_URL.to_string(),
            }
        })?;

        let token =
            credential
                .get_token(&[SCOPE], None)
                .await
                .map_err(|e: azure_core::Error| FnoxError::ProviderAuthFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details: e.to_string(),
                    hint: "Run 'az login' to authenticate with Azure".to_string(),
                    url: PROVIDER_URL.to_string(),
                })?;

        Ok(token.token.secret().to_string())
    }
}

#[async_trait]
impl crate::providers::Provider for AzureAppConfigurationProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteRead]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let key = self.get_key_name(value);
        tracing::debug!(
            "Getting key '{}' from Azure App Configuration '{}'",
            key,
            self.endpoint
        );

        // Omitting the label selects the key-value that has no label.
        let query: Vec<(&str, &str)> = match &self.label {
            Some(label) => vec![("label", label)],
            None => vec![],
        };
        let path = format!("/kv/{}", urlencoding::encode(&key));
        let response = self.get(&path, &query).await?;

        if response.status().as_u16() == 404 {
            return Err(FnoxError::ProviderSecretNotFound {
                provider: PROVIDER_NAME.to_string(),
                secret: key,
                hint: "Check the key name, prefix and label".to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }

        let kv: KeyValue =
            response
                .json()
                .await
                .map_err(|e| FnoxError::ProviderInvalidResponse {
                    provider: PROVIDER_NAME.to_string(),
                    details: format!("Failed to parse key-value response: {}", e),
                    hint: "This is an unexpected error".to_string(),
                    url: PROVIDER_URL.to_string(),
                })?;

        kv.value.ok_or_else(|| FnoxError::ProviderInvalidResponse {
            provider: PROVIDER_NAME.to_string(),
            details: format!("Key '{}' has no value", key),
            hint: "The key exists but has no value set".to_string(),
            url: PROVIDER_URL.to_string(),
        })
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!(
            "Testing connection to Azure App Configuration '{}'",
            self.endpoint
        );

        // Filtered list: proves the store is reachable and the token is accepted
        // without depending on any particular key existing.
        self.get("/kv", &[("key", "fnox-connection-test")]).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(label: Option<&str>, prefix: Option<&str>) -> AzureAppConfigurationProvider {
        AzureAppConfigurationProvider::new(
            "https://store.azconfig.io/".to_string(),
            label.map(String::from),
            prefix.map(String::from),
        )
        .unwrap()
    }

    #[test]
    fn prefix_is_prepended_to_the_key() {
        assert_eq!(provider(None, None).get_key_name("api-url"), "api-url");
        assert_eq!(
            provider(None, Some("myapp/")).get_key_name("api-url"),
            "myapp/api-url"
        );
    }

    #[test]
    fn empty_label_and_prefix_are_treated_as_unset() {
        let provider = provider(Some(""), Some(""));
        assert_eq!(provider.label, None);
        assert_eq!(provider.prefix, None);
    }

    #[test]
    fn trailing_slash_is_stripped_from_the_endpoint() {
        assert_eq!(provider(None, None).endpoint, "https://store.azconfig.io");
    }
}
