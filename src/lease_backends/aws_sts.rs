use crate::error::{FnoxError, Result};
use crate::lease_backends::{Lease, LeaseBackend};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_sts::Client;
use indexmap::IndexMap;
use std::time::Duration;

const URL: &str = "https://fnox.jdx.dev/leases/aws-sts";

pub struct AwsStsBackend {
    region: String,
    profile: Option<String>,
    role_arn: String,
    endpoint: Option<String>,
}

impl AwsStsBackend {
    pub fn new(
        region: String,
        profile: Option<String>,
        role_arn: String,
        endpoint: Option<String>,
    ) -> Self {
        Self {
            region,
            profile,
            role_arn,
            endpoint,
        }
    }

    async fn create_client(&self) -> Result<Client> {
        let mut builder = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_sts::config::Region::new(self.region.clone()));

        if let Some(profile) = &self.profile {
            builder = builder.profile_name(profile);
        }

        let config = builder.load().await;

        let mut sts_config_builder = aws_sdk_sts::config::Builder::from(&config);
        if let Some(endpoint) = &self.endpoint {
            sts_config_builder = sts_config_builder.endpoint_url(endpoint);
        }

        Ok(Client::from_conf(sts_config_builder.build()))
    }
}

#[async_trait]
impl LeaseBackend for AwsStsBackend {
    async fn create_lease(&self, duration: Duration, label: &str) -> Result<Lease> {
        let client = self.create_client().await?;
        let role_arn = &self.role_arn;

        let result = client
            .assume_role()
            .role_arn(role_arn)
            .role_session_name(sanitize_session_name(label))
            .duration_seconds(i32::try_from(duration.as_secs()).unwrap_or(i32::MAX))
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
            chrono::DateTime::from_timestamp(epoch_secs, 0).or_else(|| {
                tracing::warn!(
                    "AWS STS returned an out-of-range expiration timestamp: {}",
                    epoch_secs
                );
                None
            })
        };

        let mut creds = IndexMap::new();
        creds.insert("AWS_ACCESS_KEY_ID".to_string(), access_key);
        creds.insert("AWS_SECRET_ACCESS_KEY".to_string(), secret_key);
        creds.insert("AWS_SESSION_TOKEN".to_string(), session_token);

        // Generate a unique lease ID: combine assumed role info with timestamp
        // to avoid collisions when the same role is assumed multiple times
        let role_id = result
            .assumed_role_user()
            .map(|u| u.assumed_role_id().to_string())
            .unwrap_or_else(|| "sts".to_string());
        let lease_id = format!("{}-{}", role_id, chrono::Utc::now().timestamp_millis());

        Ok(Lease {
            credentials: creds,
            expires_at,
            lease_id,
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
}

/// Sanitize a string for use as an AWS STS role session name.
/// Session names must be 2-64 chars, matching [\w+=,.@-]+
fn sanitize_session_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "+=,.@-_".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Safe to use byte indexing since all chars are ASCII after sanitization
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
