//! Forgejo and Gitea Actions secrets, set through the REST API.
//!
//! `PUT /repos/{owner}/{repo}/actions/secrets/{name}` (or the `/orgs/{org}`
//! equivalent) creates or replaces a secret. The token comes from
//! `FORGEJO_TOKEN`, then `GITEA_TOKEN`.

use super::PushTarget;
use crate::error::{FnoxError, Result};
use crate::lease_backends::{env_credential, require_secure_url};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const TARGET_TYPE: &str = "forgejo-actions";
const TOKEN_VARS: &[&str] = &["FORGEJO_TOKEN", "GITEA_TOKEN"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForgejoActions {
    /// Base URL of the instance, such as `https://codeberg.org`
    pub url: String,
    /// Repository as `owner/name`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Organization to set the secret in, instead of a repository
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

impl ForgejoActions {
    fn endpoint(&self, name: &str) -> String {
        let base = self.url.trim_end_matches('/');
        match (&self.org, &self.repo) {
            (Some(org), _) => format!("{base}/api/v1/orgs/{org}/actions/secrets/{name}"),
            (None, Some(repo)) => format!("{base}/api/v1/repos/{repo}/actions/secrets/{name}"),
            (None, None) => unreachable!("validated: repo or org is set"),
        }
    }

    fn error(details: String) -> FnoxError {
        FnoxError::ProviderApiError {
            provider: TARGET_TYPE.to_string(),
            details,
            hint: "Check that the token can manage Actions secrets there (scope write:repository or write:organization)".to_string(),
            url: super::docs_url(TARGET_TYPE),
        }
    }
}

#[async_trait]
impl PushTarget for ForgejoActions {
    fn describe(&self) -> String {
        let place = match (&self.org, &self.repo) {
            (Some(org), _) => format!("organization {org}"),
            (None, Some(repo)) => repo.clone(),
            (None, None) => "?".to_string(),
        };
        let host = reqwest::Url::parse(&self.url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| self.url.clone());
        format!("Forgejo Actions secret in {place} on {host}")
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.repo.is_some() == self.org.is_some() {
            return Err("set exactly one of repo or org".into());
        }
        require_secure_url(TARGET_TYPE, "url", &self.url).map_err(|e| e.to_string())
    }

    async fn push(&self, name: &str, value: &str) -> Result<()> {
        let token = TOKEN_VARS
            .iter()
            .find_map(|var| env_credential(var))
            .ok_or_else(|| {
                Self::error(format!(
                    "no API token: set {} to a token for {}",
                    TOKEN_VARS.join(" or "),
                    self.url
                ))
            })?;
        let response = crate::http::credential_client()
            .put(self.endpoint(name))
            .header("Authorization", format!("token {token}"))
            .json(&serde_json::json!({ "data": value }))
            .send()
            .await
            .map_err(|e| Self::error(format!("request failed: {e}")))?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(Self::error(format!("HTTP {status}: {}", body.trim())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> ForgejoActions {
        toml_edit::de::from_str(toml).unwrap()
    }

    #[test]
    fn endpoints() {
        let t = parse("url = \"https://codeberg.org/\"\nrepo = \"acme/api\"");
        assert!(t.validate().is_ok());
        assert_eq!(
            t.endpoint("KEY"),
            "https://codeberg.org/api/v1/repos/acme/api/actions/secrets/KEY"
        );
        assert_eq!(
            t.describe(),
            "Forgejo Actions secret in acme/api on codeberg.org"
        );
        let t = parse("url = \"https://git.example.com\"\norg = \"acme\"");
        assert_eq!(
            t.endpoint("KEY"),
            "https://git.example.com/api/v1/orgs/acme/actions/secrets/KEY"
        );
    }

    #[test]
    fn rejects_bad_config() {
        assert!(parse("url = \"https://codeberg.org\"").validate().is_err());
        assert!(
            parse("url = \"https://codeberg.org\"\nrepo = \"a/b\"\norg = \"a\"")
                .validate()
                .is_err()
        );
        assert!(
            parse("url = \"http://codeberg.org\"\nrepo = \"a/b\"")
                .validate()
                .is_err()
        );
    }
}
