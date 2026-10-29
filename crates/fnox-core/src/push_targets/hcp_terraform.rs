//! HCP Terraform and Terraform Enterprise workspace variables, set through the
//! REST API.
//!
//! fnox looks up the workspace by organization and name, then updates the
//! variable with the same key and category or creates it. The token comes from
//! `TF_TOKEN_<host>`, `TFE_TOKEN`, or the credentials file `terraform login`
//! writes.

use super::PushTarget;
use crate::error::{FnoxError, Result};
use crate::lease_backends::{env_credential, require_secure_url};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const TARGET_TYPE: &str = "hcp-terraform";
const JSON_API: &str = "application/vnd.api+json";

fn default_url() -> String {
    "https://app.terraform.io".to_string()
}

fn is_default_url(url: &str) -> bool {
    url == default_url()
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

/// Whether a variable is a Terraform input variable or an environment variable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Terraform,
    Env,
}

impl Category {
    fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::Env => "env",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HcpTerraform {
    /// Base URL of HCP Terraform or your Terraform Enterprise instance
    #[serde(default = "default_url", skip_serializing_if = "is_default_url")]
    pub url: String,
    /// Organization that owns the workspace
    pub organization: String,
    /// Workspace name
    pub workspace: String,
    /// `"terraform"` for an input variable, `"env"` for an environment variable
    pub category: Category,
    /// Write the value once and never show it again (default: true)
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub sensitive: bool,
    /// Parse the value as HCL instead of a string
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hcl: bool,
    /// Description shown in HCP Terraform
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl HcpTerraform {
    fn host(&self) -> String {
        reqwest::Url::parse(&self.url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default()
    }

    fn api(&self, path: &str) -> String {
        format!("{}/api/v2{path}", self.url.trim_end_matches('/'))
    }

    fn token(&self) -> Result<String> {
        let host = self.host();
        let host_var = token_env_var(&host);
        if let Some(token) = env_credential(&host_var).or_else(|| env_credential("TFE_TOKEN")) {
            return Ok(token);
        }
        if let Some(token) = credentials_file_token(&host) {
            return Ok(token);
        }
        Err(Self::error(format!(
            "no API token: set {host_var} or TFE_TOKEN, or run `terraform login {host}`"
        )))
    }

    fn error(details: String) -> FnoxError {
        FnoxError::ProviderApiError {
            provider: TARGET_TYPE.to_string(),
            details,
            hint: "Check that the token can read and write variables in the workspace".to_string(),
            url: super::docs_url(TARGET_TYPE),
        }
    }

    async fn request(
        &self,
        token: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut request = crate::http::credential_client()
            .request(method.clone(), self.api(path))
            .bearer_auth(token)
            .header("Content-Type", JSON_API);
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request
            .send()
            .await
            .map_err(|e| Self::error(format!("{method} {path}: request failed: {e}")))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(Self::error(format!(
                "{method} {path}: HTTP {status}: {}",
                text.trim()
            )));
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text)
            .map_err(|e| Self::error(format!("{method} {path}: invalid JSON: {e}")))
    }
}

/// `TF_TOKEN_` plus the hostname, with periods as underscores and hyphens as
/// double underscores, as Terraform reads it
fn token_env_var(host: &str) -> String {
    format!("TF_TOKEN_{}", host.replace('-', "__").replace('.', "_"))
}

/// The token `terraform login` saved for `host`
fn credentials_file_token(host: &str) -> Option<String> {
    let path = if cfg!(windows) {
        dirs::config_dir()?.join("terraform.d")
    } else {
        crate::env::HOME_DIR.join(".terraform.d")
    }
    .join("credentials.tfrc.json");
    let content = std::fs::read_to_string(path).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;
    json["credentials"][host]["token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .map(String::from)
}

#[async_trait]
impl PushTarget for HcpTerraform {
    fn describe(&self) -> String {
        let kind = match self.category {
            Category::Terraform => "Terraform variable",
            Category::Env => "environment variable",
        };
        let mut place = format!(
            "HCP Terraform {kind} in {}/{}",
            self.organization, self.workspace
        );
        if !is_default_url(&self.url) {
            place.push_str(&format!(" on {}", self.host()));
        }
        place
    }

    fn validate(&self) -> std::result::Result<(), String> {
        for (field, value) in [
            ("organization", &self.organization),
            ("workspace", &self.workspace),
        ] {
            if !super::is_path_segment(value) {
                return Err(format!(
                    "{field} '{value}' must be a name of letters, digits, '-', '_' and '.'"
                ));
            }
        }
        require_secure_url(TARGET_TYPE, "url", &self.url).map_err(|e| e.to_string())
    }

    async fn push(&self, name: &str, value: &str) -> Result<()> {
        let token = self.token()?;
        let workspace = self
            .request(
                &token,
                reqwest::Method::GET,
                &format!(
                    "/organizations/{}/workspaces/{}",
                    self.organization, self.workspace
                ),
                None,
            )
            .await?;
        let workspace_id = workspace["data"]["id"]
            .as_str()
            .ok_or_else(|| Self::error("workspace response has no data.id".to_string()))?
            .to_string();

        let vars = self
            .request(
                &token,
                reqwest::Method::GET,
                &format!("/workspaces/{workspace_id}/vars"),
                None,
            )
            .await?;
        // Without the list, fnox cannot tell an update from a create
        let vars = vars["data"]
            .as_array()
            .ok_or_else(|| Self::error("variables response has no data array".to_string()))?;
        let existing = vars.iter().find(|v| {
            v["attributes"]["key"] == name && v["attributes"]["category"] == self.category.as_str()
        });

        let mut attributes = json!({
            "value": value,
            "sensitive": self.sensitive,
            "hcl": self.hcl,
        });
        if let Some(description) = &self.description {
            attributes["description"] = json!(description);
        }
        match existing.and_then(|v| v["id"].as_str()) {
            Some(var_id) => {
                let body =
                    json!({ "data": { "type": "vars", "id": var_id, "attributes": attributes } });
                self.request(
                    &token,
                    reqwest::Method::PATCH,
                    &format!("/workspaces/{workspace_id}/vars/{var_id}"),
                    Some(body),
                )
                .await?;
            }
            None => {
                attributes["key"] = json!(name);
                attributes["category"] = json!(self.category.as_str());
                let body = json!({ "data": { "type": "vars", "attributes": attributes } });
                self.request(
                    &token,
                    reqwest::Method::POST,
                    &format!("/workspaces/{workspace_id}/vars"),
                    Some(body),
                )
                .await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> HcpTerraform {
        toml_edit::de::from_str(toml).unwrap()
    }

    #[test]
    fn defaults() {
        let t = parse("organization = \"acme\"\nworkspace = \"prod\"\ncategory = \"env\"");
        assert_eq!(t.url, "https://app.terraform.io");
        assert!(t.sensitive);
        assert!(!t.hcl);
        assert!(t.validate().is_ok());
        assert_eq!(t.api("/x"), "https://app.terraform.io/api/v2/x");
        assert_eq!(
            t.describe(),
            "HCP Terraform environment variable in acme/prod"
        );
    }

    #[test]
    fn rejects_names_that_change_the_path() {
        let t = parse("organization = \"acme\"\nworkspace = \"prod?x=1\"\ncategory = \"env\"");
        assert!(t.validate().is_err());
        let t = parse("organization = \"../admin\"\nworkspace = \"prod\"\ncategory = \"env\"");
        assert!(t.validate().is_err());
    }

    #[test]
    fn token_env_var_encodes_host() {
        assert_eq!(
            token_env_var("app.terraform.io"),
            "TF_TOKEN_app_terraform_io"
        );
        assert_eq!(
            token_env_var("tfe.my-corp.com"),
            "TF_TOKEN_tfe_my__corp_com"
        );
    }
}
