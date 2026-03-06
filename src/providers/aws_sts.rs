use crate::error::{FnoxError, Result};
use crate::providers::{CredentialPrompt, Lease, LeaseProvider, ProviderCapability};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_sts::Client;
use std::collections::HashMap;
use std::time::Duration;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

const URL: &str = "https://fnox.jdx.dev/providers/aws-sts";

pub struct AwsStsProvider {
    region: String,
    profile: Option<String>,
    role_arn: Option<String>,
}

impl AwsStsProvider {
    pub fn new(region: String, profile: Option<String>, role_arn: Option<String>) -> Self {
        Self {
            region,
            profile,
            role_arn,
        }
    }

    async fn create_client(&self) -> Result<Client> {
        let mut builder = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_sts::config::Region::new(self.region.clone()));

        if let Some(profile) = &self.profile {
            builder = builder.profile_name(profile);
        }

        let config = builder.load().await;
        Ok(Client::new(&config))
    }

    fn resolve_role_arn(&self, value: &str) -> String {
        // If value looks like an ARN, use it directly; otherwise use default role_arn
        if value.starts_with("arn:") {
            value.to_string()
        } else if let Some(ref default_arn) = self.role_arn {
            default_arn.clone()
        } else {
            value.to_string()
        }
    }
}

#[async_trait]
impl crate::providers::Provider for AwsStsProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::Leasing]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        // STS provider doesn't store secrets - it creates leases.
        // get_secret creates a short-lived credential with default duration.
        let lease = self
            .create_lease(value, Duration::from_secs(900), "fnox-get")
            .await?;
        // Return the session token as the "secret" for backward compatibility
        lease
            .credentials
            .get("AWS_SESSION_TOKEN")
            .cloned()
            .ok_or_else(|| {
                FnoxError::Provider("AWS STS AssumeRole did not return a session token".to_string())
            })
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client().await?;
        client
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "AWS STS".to_string(),
                details: e.to_string(),
                hint: "Check AWS credentials and permissions".to_string(),
                url: URL.to_string(),
            })?;
        Ok(())
    }

    fn as_lease_provider(&self) -> Option<&dyn LeaseProvider> {
        Some(self)
    }
}

#[async_trait]
impl LeaseProvider for AwsStsProvider {
    async fn create_lease(&self, value: &str, duration: Duration, label: &str) -> Result<Lease> {
        let client = self.create_client().await?;
        let role_arn = self.resolve_role_arn(value);

        let result = client
            .assume_role()
            .role_arn(&role_arn)
            .role_session_name(sanitize_session_name(label))
            .duration_seconds(duration.as_secs() as i32)
            .send()
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("AccessDenied") || err_str.contains("not authorized") {
                    FnoxError::ProviderAuthFailed {
                        provider: "AWS STS".to_string(),
                        details: err_str,
                        hint: format!("Check IAM permissions for sts:AssumeRole on '{}'", role_arn),
                        url: URL.to_string(),
                    }
                } else {
                    FnoxError::ProviderApiError {
                        provider: "AWS STS".to_string(),
                        details: err_str,
                        hint: "Check AWS STS configuration and role ARN".to_string(),
                        url: URL.to_string(),
                    }
                }
            })?;

        let credentials =
            result
                .credentials()
                .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                    provider: "AWS STS".to_string(),
                    details: "AssumeRole response missing credentials".to_string(),
                    hint: "Unexpected AWS STS response".to_string(),
                    url: URL.to_string(),
                })?;

        let access_key = credentials.access_key_id().to_string();
        let secret_key = credentials.secret_access_key().to_string();
        let session_token = credentials.session_token().to_string();
        let expiration = credentials.expiration();

        let expires_at = {
            let epoch_secs = expiration.secs();
            chrono::DateTime::from_timestamp(epoch_secs, 0)
        };

        let mut creds = HashMap::new();
        creds.insert("AWS_ACCESS_KEY_ID".to_string(), access_key);
        creds.insert("AWS_SECRET_ACCESS_KEY".to_string(), secret_key);
        creds.insert("AWS_SESSION_TOKEN".to_string(), session_token);

        // Generate a unique lease ID from the assumed role info
        let lease_id = result
            .assumed_role_user()
            .map(|u| u.assumed_role_id().to_string())
            .unwrap_or_else(|| format!("sts-{}", chrono::Utc::now().timestamp()));

        Ok(Lease {
            credentials: creds,
            expires_at,
            lease_id,
            description: format!("AWS STS AssumeRole: {}", role_arn),
        })
    }

    async fn revoke_lease(&self, _lease_id: &str) -> Result<()> {
        // AWS STS credentials have native TTL, no manual revocation needed
        Ok(())
    }

    fn max_lease_duration(&self) -> Duration {
        // AWS STS default max is 12 hours (can be configured per-role up to 12h)
        Duration::from_secs(12 * 3600)
    }

    fn credential_prompts(&self) -> Vec<CredentialPrompt> {
        vec![
            CredentialPrompt {
                name: "AWS_ACCESS_KEY_ID".to_string(),
                label: "AWS Access Key ID".to_string(),
                secret: false,
            },
            CredentialPrompt {
                name: "AWS_SECRET_ACCESS_KEY".to_string(),
                label: "AWS Secret Access Key".to_string(),
                secret: true,
            },
        ]
    }
}

/// Sanitize a string for use as an AWS STS role session name.
/// Session names must be 2-64 chars, matching [\w+=,.@-]+
fn sanitize_session_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || "+=,.@-_".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();

    if sanitized.len() > 64 {
        sanitized[..64].to_string()
    } else if sanitized.len() < 2 {
        format!("{:_<2}", sanitized)
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_session_name() {
        assert_eq!(sanitize_session_name("my-session"), "my-session");
        assert_eq!(sanitize_session_name("a"), "a_");
        assert_eq!(
            sanitize_session_name("has spaces and !special"),
            "has-spaces-and--special"
        );
        let long = "a".repeat(100);
        assert_eq!(sanitize_session_name(&long).len(), 64);
    }
}
