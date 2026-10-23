use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/gitlab";
const PROVIDER: &str = "GitLab";
const DEFAULT_BASE_URL: &str = "https://gitlab.com";
const TOKEN_NAME_PREFIX: &str = "fnox-lease-";

/// GitLab expiry has one-day granularity, so there is no point leasing longer.
const MAX_DURATION_SECS: u64 = 24 * 3600;

/// All env var names the GitLab backend may consume at runtime.
pub const CONSUMED_ENV_VARS: &[&str] = &["GITLAB_TOKEN"];

pub fn check_prerequisites() -> Option<String> {
    if std::env::var("GITLAB_TOKEN").is_ok() {
        None
    } else {
        Some("GitLab token not found. Set GITLAB_TOKEN to a token with the 'api' scope and the Maintainer role on the project or group.".to_string())
    }
}

pub fn required_env_vars() -> Vec<(&'static str, &'static str)> {
    vec![(
        "GITLAB_TOKEN",
        "GitLab token with the 'api' scope and Maintainer role on the project or group",
    )]
}

pub struct GitLabBackend {
    base_url: String,
    /// Path segment under `/api/v4`, such as `projects/group%2Fapp`.
    owner_path: String,
    scopes: Vec<String>,
    access_level: u32,
    env_var: String,
}

/// Map an access level name to GitLab's numeric role.
fn access_level_value(name: &str) -> Result<u32> {
    match name {
        "guest" => Ok(10),
        "reporter" => Ok(20),
        "developer" => Ok(30),
        "maintainer" => Ok(40),
        "owner" => Ok(50),
        other => Err(FnoxError::Config(format!(
            "GitLab backend: invalid access_level '{other}'. \
             Use guest, reporter, developer, maintainer, or owner."
        ))),
    }
}

impl GitLabBackend {
    pub fn new(
        url: Option<String>,
        project: Option<String>,
        group: Option<String>,
        scopes: Vec<String>,
        access_level: &str,
        env_var: String,
    ) -> Result<Self> {
        let owner_path = match (project, group) {
            (Some(project), None) => format!("projects/{}", urlencoding::encode(&project)),
            (None, Some(group)) => format!("groups/{}", urlencoding::encode(&group)),
            _ => {
                return Err(FnoxError::Config(
                    "GitLab backend: set exactly one of 'project' or 'group'.".to_string(),
                ));
            }
        };
        if scopes.is_empty() {
            return Err(FnoxError::Config(
                "GitLab backend: 'scopes' must contain at least one scope.".to_string(),
            ));
        }
        let base_url = url
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            base_url,
            owner_path,
            scopes,
            access_level: access_level_value(access_level)?,
            env_var,
        })
    }

    fn get_parent_token() -> Result<String> {
        std::env::var("GITLAB_TOKEN").map_err(|_| FnoxError::ProviderAuthFailed {
            provider: PROVIDER.to_string(),
            details: "No parent token found".to_string(),
            hint: "Set GITLAB_TOKEN to a token with the 'api' scope and the Maintainer role"
                .to_string(),
            url: URL.to_string(),
        })
    }

    fn tokens_url(&self) -> String {
        format!("{}/api/v4/{}/access_tokens", self.base_url, self.owner_path)
    }
}

/// GitLab reports errors as `{"message": ...}` or `{"error": ...}`, where
/// `message` may be a string or a structure.
fn error_text(status: reqwest::StatusCode, body: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    match (&parsed["message"], &parsed["error"]) {
        (serde_json::Value::String(message), _) => message.clone(),
        (serde_json::Value::Null, serde_json::Value::String(error)) => error.clone(),
        (serde_json::Value::Null, _) if body.trim().is_empty() => format!("HTTP {status}"),
        (serde_json::Value::Null, _) => format!("HTTP {status}: {}", body.trim()),
        (message, _) => message.to_string(),
    }
}

#[async_trait]
impl LeaseBackend for GitLabBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let parent_token = Self::get_parent_token()?;

        let now = chrono::Utc::now();
        let expires_at =
            now + chrono::Duration::seconds(duration.as_secs().min(i64::MAX as u64) as i64);
        // GitLab only accepts a date, and a token stops working at the start of
        // that day. Use the day after the lease ends so the token outlives the
        // lease; revoking it at cleanup closes the extra window.
        let expires_date = expires_at.date_naive() + chrono::Duration::days(1);

        let body = serde_json::json!({
            "name": format!("{TOKEN_NAME_PREFIX}{label}"),
            "scopes": self.scopes,
            "access_level": self.access_level,
            "expires_at": expires_date.format("%Y-%m-%d").to_string(),
        });

        let client = crate::http::http_client();
        let response = client
            .post(self.tokens_url())
            .header("PRIVATE-TOKEN", &parent_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: format!("Failed to connect to GitLab at {}", self.base_url),
                url: URL.to_string(),
            })?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            let details = error_text(status, &text);
            return Err(if matches!(status.as_u16(), 401 | 403) {
                FnoxError::ProviderAuthFailed {
                    provider: PROVIDER.to_string(),
                    details,
                    hint: "Check that GITLAB_TOKEN has the 'api' scope and the Maintainer role"
                        .to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: PROVIDER.to_string(),
                    details,
                    hint: "Check project, group, scopes and access_level".to_string(),
                    url: URL.to_string(),
                }
            });
        }

        let resp: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: "Unexpected response from GitLab API".to_string(),
                url: URL.to_string(),
            })?;

        let missing = |field: &str| FnoxError::ProviderInvalidResponse {
            provider: PROVIDER.to_string(),
            details: format!("Response missing '{field}' field"),
            hint: "Unexpected response from GitLab API".to_string(),
            url: URL.to_string(),
        };
        let token = resp["token"].as_str().ok_or_else(|| missing("token"))?;
        let token_id = resp["id"].as_u64().ok_or_else(|| missing("id"))?;

        let mut credentials = IndexMap::new();
        credentials.insert(self.env_var.clone(), token.to_string());

        Ok(Lease {
            credentials,
            expires_at: Some(expires_at),
            lease_id: token_id.to_string(),
        })
    }

    async fn revoke_lease(
        &self,
        lease_id: &str,
        _credentials: Option<&IndexMap<String, String>>,
    ) -> Result<()> {
        let parent_token = Self::get_parent_token()?;

        let client = crate::http::http_client();
        let response = client
            .delete(format!("{}/{}", self.tokens_url(), lease_id))
            .header("PRIVATE-TOKEN", &parent_token)
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: e.to_string(),
                hint: "Failed to connect to GitLab for token revocation".to_string(),
                url: URL.to_string(),
            })?;

        let status = response.status();
        // 404 = token already deleted or expired and cleaned up
        if status.is_success() || status.as_u16() == 404 {
            return Ok(());
        }
        let text = response.text().await.unwrap_or_default();
        let details = error_text(status, &text);
        Err(if matches!(status.as_u16(), 401 | 403) {
            FnoxError::ProviderAuthFailed {
                provider: PROVIDER.to_string(),
                details,
                hint: "Check that GITLAB_TOKEN has the 'api' scope and the Maintainer role"
                    .to_string(),
                url: URL.to_string(),
            }
        } else {
            FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details,
                hint: "Failed to revoke GitLab access token".to_string(),
                url: URL.to_string(),
            }
        })
    }

    fn max_lease_duration(&self) -> Duration {
        Duration::from_secs(MAX_DURATION_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(project: Option<&str>, group: Option<&str>) -> Result<GitLabBackend> {
        GitLabBackend::new(
            None,
            project.map(str::to_string),
            group.map(str::to_string),
            vec!["read_api".to_string()],
            "developer",
            "GITLAB_TOKEN".to_string(),
        )
    }

    #[test]
    fn requires_exactly_one_of_project_or_group() {
        assert!(backend(None, None).is_err());
        assert!(backend(Some("a/b"), Some("a")).is_err());
        assert!(backend(Some("a/b"), None).is_ok());
        assert!(backend(None, Some("a")).is_ok());
    }

    #[test]
    fn encodes_the_project_path() {
        let b = backend(Some("group/sub/app"), None).unwrap();
        assert_eq!(
            b.tokens_url(),
            "https://gitlab.com/api/v4/projects/group%2Fsub%2Fapp/access_tokens"
        );
    }

    #[test]
    fn trims_trailing_slash_from_self_hosted_url() {
        let b = GitLabBackend::new(
            Some("https://git.example.com/".to_string()),
            None,
            Some("42".to_string()),
            vec!["read_api".to_string()],
            "maintainer",
            "GITLAB_TOKEN".to_string(),
        )
        .unwrap();
        assert_eq!(
            b.tokens_url(),
            "https://git.example.com/api/v4/groups/42/access_tokens"
        );
    }

    #[test]
    fn maps_access_levels() {
        assert_eq!(access_level_value("guest").unwrap(), 10);
        assert_eq!(access_level_value("developer").unwrap(), 30);
        assert_eq!(access_level_value("owner").unwrap(), 50);
        assert!(access_level_value("admin").is_err());
    }

    #[test]
    fn rejects_empty_scopes() {
        let result = GitLabBackend::new(
            None,
            Some("a/b".to_string()),
            None,
            vec![],
            "developer",
            "GITLAB_TOKEN".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn reads_error_message_shapes() {
        let status = reqwest::StatusCode::BAD_REQUEST;
        assert_eq!(error_text(status, r#"{"message":"nope"}"#), "nope");
        assert_eq!(error_text(status, r#"{"error":"bad"}"#), "bad");
        assert_eq!(
            error_text(status, r#"{"message":{"expires_at":["is invalid"]}}"#),
            r#"{"expires_at":["is invalid"]}"#
        );
        assert_eq!(error_text(status, ""), "HTTP 400 Bad Request");
    }
}
