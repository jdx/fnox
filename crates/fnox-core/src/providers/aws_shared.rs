use crate::error::{FnoxError, Result};
use aws_config::{BehaviorVersion, SdkConfig, sts::AssumeRoleProvider};
use aws_sdk_sts::config::{Region, SharedCredentialsProvider};

/// Build the base `SdkConfig` for an AWS provider, optionally assuming a role.
///
/// `profile` selects the source credentials (including SSO). When `role_arn` is set, those
/// credentials are only used to call `sts:AssumeRole`, and the returned config carries the
/// assumed role's credentials instead.
pub async fn load_sdk_config(
    region: &str,
    profile: Option<&str>,
    role_arn: Option<&str>,
) -> Result<SdkConfig> {
    let region = Region::new(region.to_string());

    let mut builder = aws_config::defaults(BehaviorVersion::latest()).region(region.clone());
    if let Some(profile) = profile {
        builder = builder.profile_name(profile);
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

fn validate_role_arn(role_arn: &str) -> Result<()> {
    if role_arn.starts_with("arn:") && role_arn.contains(":iam:") && role_arn.contains(":role/") {
        return Ok(());
    }
    Err(FnoxError::Config(format!(
        "'{role_arn}' is not a valid IAM role ARN - expected arn:aws:iam::123456789012:role/my-role"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_role_arn() {
        assert!(validate_role_arn("arn:aws:iam::123456789012:role/my-role").is_ok());
        assert!(validate_role_arn("arn:aws-us-gov:iam::123456789012:role/my-role").is_ok());
        assert!(validate_role_arn("arn:aws:iam::123456789012:role/path/to/my-role").is_ok());
        assert!(validate_role_arn("my-role").is_err());
        assert!(validate_role_arn("arn:aws:iam::123456789012:user/me").is_err());
        assert!(validate_role_arn("arn:aws:kms:us-east-1:123456789012:key/abc").is_err());
    }
}
