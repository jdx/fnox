use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Environment variable fallback for API key
static PASSWORDSTATE_API_KEY: LazyLock<Option<String>> = LazyLock::new(|| {
    env::var("FNOX_PASSWORDSTATE_API_KEY")
        .or_else(|_| env::var("PASSWORDSTATE_API_KEY"))
        .ok()
});

/// Password entry returned from Passwordstate API
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PasswordEntry {
    #[serde(default)]
    #[allow(dead_code)]
    password_id: i64,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    user_name: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

pub struct PasswordstateProvider {
    base_url: String,
    api_key: String,
    password_list_id: String,
    verify_ssl: bool,
}

impl PasswordstateProvider {
    pub fn new(
        base_url: String,
        api_key: Option<String>,
        password_list_id: String,
        verify_ssl: Option<String>,
    ) -> Self {
        let api_key = api_key
            .or_else(|| PASSWORDSTATE_API_KEY.clone())
            .unwrap_or_default();

        let verify_ssl = verify_ssl
            .map(|v| v.to_lowercase() != "false")
            .unwrap_or(true);

        // Normalize base_url (remove trailing slash)
        let base_url = base_url.trim_end_matches('/').to_string();

        Self {
            base_url,
            api_key,
            password_list_id,
            verify_ssl,
        }
    }

    /// Create an HTTP client with appropriate SSL settings
    fn create_client(&self) -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(!self.verify_ssl)
            .build()
            .map_err(|e| FnoxError::Provider(format!("Failed to create HTTP client: {}", e)))
    }

    /// Parse value reference into (identifier, field, is_id)
    ///
    /// Supported formats:
    /// - `123` (numeric) - Password ID, returns password field
    /// - `123/field` - Password ID with specific field
    /// - `title` (non-numeric) - Search by title, returns password field
    /// - `title/field` - Search by title, get specific field
    fn parse_reference(&self, value: &str) -> Result<(String, String, bool)> {
        let parts: Vec<&str> = value.split('/').collect();

        match parts.len() {
            1 => {
                let is_id = parts[0].parse::<i64>().is_ok();
                Ok((parts[0].to_string(), "password".to_string(), is_id))
            }
            2 => {
                let is_id = parts[0].parse::<i64>().is_ok();
                Ok((parts[0].to_string(), parts[1].to_lowercase(), is_id))
            }
            _ => Err(FnoxError::Provider(format!(
                "Invalid Passwordstate reference format: '{}'. Expected 'id', 'id/field', 'title', or 'title/field'",
                value
            ))),
        }
    }

    /// Get a password entry by its ID
    async fn get_by_id(&self, password_id: &str) -> Result<PasswordEntry> {
        let client = self.create_client()?;
        let url = format!("{}/api/passwords/{}", self.base_url, password_id);

        tracing::debug!("Fetching password by ID from: {}", url);

        let response = client
            .get(&url)
            .header("APIKey", &self.api_key)
            .send()
            .await
            .map_err(|e| FnoxError::Provider(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(FnoxError::Provider(format!(
                "Passwordstate API error (HTTP {}): {}",
                status, body
            )));
        }

        // API returns an array even for single password
        let entries: Vec<PasswordEntry> = response.json().await.map_err(|e| {
            FnoxError::Provider(format!("Failed to parse Passwordstate response: {}", e))
        })?;

        entries.into_iter().next().ok_or_else(|| {
            FnoxError::Provider(format!("Password with ID '{}' not found", password_id))
        })
    }

    /// Extract a specific field from a password entry
    fn extract_field(entry: &PasswordEntry, field: &str) -> Result<String> {
        let value = match field {
            "password" => entry.password.clone(),
            "username" | "user" => entry.user_name.clone(),
            "title" => entry.title.clone(),
            "url" => entry.url.clone(),
            "description" => entry.description.clone(),
            "notes" => entry.notes.clone(),
            _ => None,
        };

        value.ok_or_else(|| {
            FnoxError::Provider(format!(
                "Field '{}' not found or empty in password entry",
                field
            ))
        })
    }

    /// Search for a password by title within the configured list
    async fn search_by_title(&self, title: &str) -> Result<PasswordEntry> {
        let client = self.create_client()?;

        // URL encode the title for the query parameter
        let encoded_title = urlencoding::encode(title);
        let url = format!(
            "{}/api/searchpasswords/{}?Title={}",
            self.base_url, self.password_list_id, encoded_title
        );

        tracing::debug!("Searching for password by title: {}", url);

        let response = client
            .get(&url)
            .header("APIKey", &self.api_key)
            .send()
            .await
            .map_err(|e| FnoxError::Provider(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(FnoxError::Provider(format!(
                "Passwordstate API error (HTTP {}): {}",
                status, body
            )));
        }

        let entries: Vec<PasswordEntry> = response.json().await.map_err(|e| {
            FnoxError::Provider(format!("Failed to parse Passwordstate response: {}", e))
        })?;

        // Find exact title match (case-insensitive)
        entries
            .into_iter()
            .find(|e| {
                e.title
                    .as_ref()
                    .map(|t| t.eq_ignore_ascii_case(title))
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                FnoxError::Provider(format!(
                    "Password '{}' not found in password list {}",
                    title, self.password_list_id
                ))
            })
    }
}

#[async_trait]
impl crate::providers::Provider for PasswordstateProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteRead]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Passwordstate", value);

        let (identifier, field, is_id) = self.parse_reference(value)?;

        let entry = if is_id {
            self.get_by_id(&identifier).await?
        } else {
            self.search_by_title(&identifier).await?
        };

        Self::extract_field(&entry, &field)
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        // Passwordstate doesn't have a batch API, so we fetch in parallel
        use futures::stream::{self, StreamExt};

        let secrets_vec: Vec<_> = secrets.to_vec();

        let results: Vec<_> = stream::iter(secrets_vec)
            .map(|(key, value)| async move {
                let result = self.get_secret(&value).await;
                (key, result)
            })
            .buffer_unordered(10)
            .collect()
            .await;

        results.into_iter().collect()
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client()?;

        // Try to access the password list to verify connection and authentication
        let url = format!("{}/api/passwords/{}", self.base_url, self.password_list_id);

        tracing::debug!("Testing Passwordstate connection: {}", url);

        let response = client
            .get(&url)
            .header("APIKey", &self.api_key)
            .send()
            .await
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to connect to Passwordstate at '{}': {}",
                    self.base_url, e
                ))
            })?;

        if !response.status().is_success() {
            return Err(FnoxError::Provider(format!(
                "Passwordstate connection test failed: HTTP {}",
                response.status()
            )));
        }

        tracing::debug!("Passwordstate connection test successful");

        Ok(())
    }
}
