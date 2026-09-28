use crate::error::{FnoxError, Result};
use aws_config::{BehaviorVersion, SdkConfig, sts::AssumeRoleProvider};
use aws_sdk_sts::config::{Region, SharedCredentialsProvider};

/// Build the base `SdkConfig` for an AWS provider, optionally assuming a role.
///
/// `profile` selects the source credentials (including SSO). When `role_arn` is set, those
/// credentials are only used to call `sts:AssumeRole`, and the returned config carries the
/// assumed role's credentials instead.
///
/// `endpoint` is applied to the config itself, not just to the caller's service client, so the
/// AssumeRole call also goes to that endpoint rather than to real AWS.
pub async fn load_sdk_config(
    region: &str,
    profile: Option<&str>,
    role_arn: Option<&str>,
    endpoint: Option<&str>,
) -> Result<SdkConfig> {
    let region = Region::new(region.to_string());

    let mut builder = aws_config::defaults(BehaviorVersion::latest()).region(region.clone());
    if let Some(profile) = profile {
        builder = builder.profile_name(profile);
    }
    if let Some(endpoint) = endpoint {
        builder = builder.endpoint_url(endpoint);
    }
    let base = builder.load().await;

    let Some(role_arn) = role_arn else {
        return Ok(base);
    };

    validate_role_arn(role_arn)?;

    let credentials = AssumeRoleProvider::builder(role_arn)
        .configure(&base)
        .region(region)
        .session_name("fnox")
        .build()
        .await;

    Ok(base
        .into_builder()
        .credentials_provider(SharedCredentialsProvider::new(credentials))
        .build())
}

/// IAM role ARNs are `arn:<partition>:iam::<account>:role/<name>` - the region segment is always
/// empty and the account is always 12 digits.
fn validate_role_arn(role_arn: &str) -> Result<()> {
    let invalid = || {
        FnoxError::Config(format!(
            "'{role_arn}' is not a valid IAM role ARN - expected arn:aws:iam::123456789012:role/my-role"
        ))
    };

    let segments: Vec<&str> = role_arn.splitn(6, ':').collect();
    let [arn, partition, service, region, account, resource] = segments[..] else {
        return Err(invalid());
    };

    if arn != "arn" || partition.is_empty() || service != "iam" || !region.is_empty() {
        return Err(invalid());
    }
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    match resource.strip_prefix("role/") {
        Some(name) if !name.is_empty() => Ok(()),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_role_arn_accepts_valid() {
        assert!(validate_role_arn("arn:aws:iam::123456789012:role/my-role").is_ok());
        assert!(validate_role_arn("arn:aws-us-gov:iam::123456789012:role/my-role").is_ok());
        assert!(validate_role_arn("arn:aws-cn:iam::123456789012:role/my-role").is_ok());
        assert!(validate_role_arn("arn:aws:iam::123456789012:role/path/to/my-role").is_ok());
    }

    #[test]
    fn test_validate_role_arn_rejects_invalid() {
        assert!(validate_role_arn("my-role").is_err());
        assert!(validate_role_arn("arn:aws:iam::123456789012:user/me").is_err());
        assert!(validate_role_arn("arn:aws:kms:us-east-1:123456789012:key/abc").is_err());
        // Substrings alone are not enough: a region, a short or non-numeric account, an empty
        // role name, or a missing segment all make the ARN unusable.
        assert!(validate_role_arn("arn:aws:iam:us-east-1:123456789012:role/my-role").is_err());
        assert!(validate_role_arn("arn:aws:iam::not-an-account:role/my-role").is_err());
        assert!(validate_role_arn("arn:aws:iam::12345:role/my-role").is_err());
        assert!(validate_role_arn("arn:aws:iam::123456789012:role/").is_err());
        assert!(validate_role_arn("arn::iam::123456789012:role/my-role").is_err());
        assert!(validate_role_arn("arn:aws:iam::123456789012").is_err());
    }
}
