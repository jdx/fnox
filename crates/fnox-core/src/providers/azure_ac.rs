use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;
use reqwest::Url;
use serde::Deserialize;

const PROVIDER_NAME: &str = "Azure App Configuration";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/azure-ac";
const API_VERSION: &str = "2023-11-01";

/// App Configuration domains and the Entra audience each cloud expects. Sending
/// a token anywhere else would hand it to whoever the endpoint points at, so an
/// unlisted domain is rejected rather than defaulted.
const CLOUDS: &[(&str, &str)] = &[
    ("azconfig.io", "https://appconfig.azure.com/.default"),
    (
        "appconfig.azure.com",
        "https://appconfig.azure.com/.default",
    ),
    ("azconfig.azure.us", "https://appconfig.azure.us/.default"),
    ("appconfig.azure.us", "https://appconfig.azure.us/.default"),
    ("azconfig.azure.cn", "https://appconfig.azure.cn/.default"),
    ("appconfig.azure.cn", "https://appconfig.azure.cn/.default"),
];

/// The audience for a store host, or None if the host is not an App Configuration domain.
fn scope_for(host: &str) -> Option<&'static str> {
    let host = host.to_ascii_lowercase();
    CLOUDS.iter().find_map(|(domain, scope)| {
        // Require a label boundary so evilazconfig.io does not pass as azconfig.io.
        host.strip_suffix(domain)
            .is_some_and(|store| store.ends_with('.'))
            .then_some(*scope)
    })
}

fn invalid_endpoint(endpoint: &str, reason: &str) -> FnoxError {
    FnoxError::Config(format!(
        "{PROVIDER_NAME}: endpoint '{endpoint}' {reason}. \
         Expected an App Configuration store such as https://my-store.azconfig.io"
    ))
}

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

#[derive(Deserialize)]
struct KeyValue {
    value: Option<String>,
}

/// A store always answers the list endpoint with an `items` array, so a 200 that
/// does not deserialise came from something that is not App Configuration.
fn validate_kv_list(body: &str) -> Result<()> {
    #[derive(Deserialize)]
    struct KeyValueList {
        #[allow(dead_code)]
        items: Vec<serde::de::IgnoredAny>,
    }

    serde_json::from_str::<KeyValueList>(body)
        .map(|_| ())
        .map_err(|e| FnoxError::ProviderInvalidResponse {
            provider: PROVIDER_NAME.to_string(),
            details: format!("Endpoint did not return a key-value list: {}", e),
            hint: "Check that the endpoint is your App Configuration store".to_string(),
            url: PROVIDER_URL.to_string(),
        })
}

pub struct AzureAppConfigurationProvider {
    endpoint: String,
    label: Option<String>,
    prefix: Option<String>,
    scope: &'static str,
}

impl AzureAppConfigurationProvider {
    pub fn new(endpoint: String, label: Option<String>, prefix: Option<String>) -> Result<Self> {
        let url = Url::parse(&endpoint).map_err(|e| invalid_endpoint(&endpoint, &e.to_string()))?;
        if url.scheme() != "https" {
            return Err(invalid_endpoint(&endpoint, "must use https"));
        }
        // host_str() ignores userinfo, so https://store.azconfig.io@example.com is example.com.
        let scope = url
            .host_str()
            .and_then(scope_for)
            .ok_or_else(|| invalid_endpoint(&endpoint, "is not an App Configuration domain"))?;

        // App Configuration has no empty label: the unlabelled key-value is the \0 label.
        Ok(Self {
            // The origin drops any path, query or fragment the endpoint carried.
            endpoint: url.origin().ascii_serialization(),
            label: label.filter(|l| !l.is_empty()),
            prefix: prefix.filter(|p| !p.is_empty()),
            scope,
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
                .get_token(&[self.scope], None)
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
        let response = self.get("/kv", &[("key", "fnox-connection-test")]).await?;

        // get() passes 404 through for get_secret; on the list endpoint it means
        // the endpoint is not an App Configuration store.
        if !response.status().is_success() {
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: format!("HTTP {}", response.status()),
                hint: "Check the store endpoint".to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Failed to read the key-value list: {}", e),
                hint: "Check that the endpoint is your App Configuration store".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;
        validate_kv_list(&body)
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
    fn scope_follows_the_endpoint_cloud() {
        assert_eq!(
            scope_for("store.azconfig.io"),
            Some("https://appconfig.azure.com/.default")
        );
        assert_eq!(
            scope_for("store.azconfig.azure.us"),
            Some("https://appconfig.azure.us/.default")
        );
        assert_eq!(
            scope_for("STORE.APPCONFIG.AZURE.CN"),
            Some("https://appconfig.azure.cn/.default")
        );
    }

    #[test]
    fn endpoint_is_reduced_to_its_origin() {
        assert_eq!(provider(None, None).endpoint, "https://store.azconfig.io");

        let with_path = AzureAppConfigurationProvider::new(
            "https://store.azconfig.io/some/path?q=1#frag".to_string(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(with_path.endpoint, "https://store.azconfig.io");
    }

    /// The token is only ever sent to the endpoint, so anything that is not a real
    /// App Configuration host has to be refused before a token is acquired.
    #[test]
    fn untrusted_endpoints_are_rejected() {
        for endpoint in [
            "http://store.azconfig.io",              // not https
            "https://example.com",                   // arbitrary host
            "https://evilazconfig.io",               // no label boundary
            "https://azconfig.io",                   // bare domain, no store
            "https://store.azconfig.io@example.com", // userinfo, host is example.com
            "https://example.com/store.azconfig.io", // domain hidden in the path
            "https://example.com/?x=store.azconfig.io",
            "not a url",
        ] {
            assert!(
                AzureAppConfigurationProvider::new(endpoint.to_string(), None, None).is_err(),
                "expected {endpoint} to be rejected"
            );
        }
    }

    /// A 200 alone does not prove the endpoint is a store, so the connection test
    /// has to recognise the list payload itself.
    #[test]
    fn connection_test_requires_a_key_value_list() {
        assert!(validate_kv_list(r#"{"items":[]}"#).is_ok());
        assert!(validate_kv_list(r#"{"items":[{"key":"a","value":"b"}]}"#).is_ok());

        for body in [
            r#"<html><body>Sign in to continue</body></html>"#,
            r#"{"ok":true}"#,
            r#"{"items":{}}"#,
            "",
        ] {
            assert!(
                validate_kv_list(body).is_err(),
                "expected {body:?} to be rejected"
            );
        }
    }
}
