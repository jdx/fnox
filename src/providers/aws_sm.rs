use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client;
use std::collections::HashMap;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

/// Convert AWS SDK errors to structured FnoxError with appropriate hints
fn aws_error_to_fnox<E, R>(
    err: &aws_sdk_secretsmanager::error::SdkError<E, R>,
    secret_name: &str,
) -> FnoxError
where
    E: std::fmt::Debug + std::fmt::Display,
    R: std::fmt::Debug,
{
    use aws_sdk_secretsmanager::error::SdkError;

    const URL: &str = "https://fnox.jdx.dev/providers/aws-sm";

    match err {
        SdkError::ServiceError(service_err) => {
            let err_str = service_err.err().to_string();
            if err_str.contains("ResourceNotFoundException") {
                FnoxError::ProviderSecretNotFound {
                    provider: "AWS Secrets Manager".to_string(),
                    secret: secret_name.to_string(),
                    hint: "Check that the secret exists in AWS Secrets Manager".to_string(),
                    url: URL.to_string(),
                }
            } else if err_str.contains("AccessDenied") || err_str.contains("UnauthorizedAccess") {
                FnoxError::ProviderAuthFailed {
                    provider: "AWS Secrets Manager".to_string(),
                    details: err_str,
                    hint: "Check IAM permissions for secretsmanager:GetSecretValue".to_string(),
                    url: URL.to_string(),
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "AWS Secrets Manager".to_string(),
                    details: err_str,
                    hint: "Check AWS Secrets Manager configuration".to_string(),
                    url: URL.to_string(),
                }
            }
        }
        SdkError::TimeoutError(_) => FnoxError::ProviderApiError {
            provider: "AWS Secrets Manager".to_string(),
            details: "Request timed out".to_string(),
            hint: "Check network connectivity and AWS region endpoint".to_string(),
            url: URL.to_string(),
        },
        SdkError::DispatchFailure(dispatch_err) => {
            if let Some(connector_err) = dispatch_err.as_connector_error() {
                let mut error_chain = vec![connector_err.to_string()];
                let mut source = std::error::Error::source(connector_err);
                while let Some(err) = source {
                    error_chain.push(err.to_string());
                    source = std::error::Error::source(err);
                }
                let full_error = error_chain.join(": ");

                let hint = if full_error.contains("dns error")
                    || full_error.contains("failed to lookup address")
                {
                    "DNS resolution failed - check network and AWS region"
                } else if full_error.contains("connection refused") {
                    "Connection refused - check AWS endpoint accessibility"
                } else if full_error.contains("tls")
                    || full_error.contains("ssl")
                    || full_error.contains("certificate")
                {
                    "TLS/SSL error - check certificates or proxy config"
                } else if full_error.contains("timeout") {
                    "Connection timeout - check network and firewall"
                } else if full_error.contains("No credentials")
                    || full_error.contains("Unable to load credentials")
                    || full_error.contains("expired")
                {
                    "Configure AWS credentials: run 'aws configure', 'aws sso login', or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY"
                } else {
                    "Check network connectivity"
                };

                // Use ProviderAuthFailed for credential-related errors
                if full_error.contains("credentials") || full_error.contains("expired") {
                    FnoxError::ProviderAuthFailed {
                        provider: "AWS Secrets Manager".to_string(),
                        details: full_error,
                        hint: hint.to_string(),
                        url: URL.to_string(),
                    }
                } else {
                    FnoxError::ProviderApiError {
                        provider: "AWS Secrets Manager".to_string(),
                        details: full_error,
                        hint: hint.to_string(),
                        url: URL.to_string(),
                    }
                }
            } else {
                FnoxError::ProviderApiError {
                    provider: "AWS Secrets Manager".to_string(),
                    details: format!("{:?}", dispatch_err),
                    hint: "Check network connectivity".to_string(),
                    url: URL.to_string(),
                }
            }
        }
        _ => FnoxError::ProviderApiError {
            provider: "AWS Secrets Manager".to_string(),
            details: err.to_string(),
            hint: "Check AWS configuration".to_string(),
            url: URL.to_string(),
        },
    }
}

/// Extract the secret name from an AWS Secrets Manager ARN.
/// ARN format: arn:aws:secretsmanager:region:account:secret:name-SUFFIX
/// The SUFFIX is a 6-character random string added by AWS.
///
/// If the input is not an ARN (doesn't start with "arn:"), returns it as-is.
fn extract_name_from_arn(arn_or_name: &str) -> String {
    // If it's not an ARN, return as-is
    if !arn_or_name.starts_with("arn:") {
        return arn_or_name.to_string();
    }

    // Split ARN by colons and get the last part (name-SUFFIX)
    if let Some(name_with_suffix) = arn_or_name.rsplit(':').next() {
        // AWS adds a 7-character suffix (hyphen + 6 random chars) to secret names in ARNs
        // We need to remove this to get the original name
        if name_with_suffix.len() > 7 {
            // Remove the last 7 characters (-XXXXXX)
            return name_with_suffix[..name_with_suffix.len() - 7].to_string();
        }
        return name_with_suffix.to_string();
    }

    // Fallback: return the original string
    arn_or_name.to_string()
}

pub struct AwsSecretsManagerProvider {
    region: String,
    prefix: Option<String>,
}

impl AwsSecretsManagerProvider {
    pub fn new(region: String, prefix: Option<String>) -> Self {
        Self { region, prefix }
    }

    pub fn get_secret_name(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}{}", prefix, key),
            None => key.to_string(),
        }
    }

    /// Create an AWS Secrets Manager client
    async fn create_client(&self) -> Result<Client> {
        // Load AWS config with the specified region
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_secretsmanager::config::Region::new(
                self.region.clone(),
            ))
            .load()
            .await;

        Ok(Client::new(&config))
    }

    /// Get a secret value from AWS Secrets Manager
    async fn get_secret_value(&self, secret_name: &str) -> Result<String> {
        let client = self.create_client().await?;

        let result = client
            .get_secret_value()
            .secret_id(secret_name)
            .send()
            .await
            .map_err(|e| aws_error_to_fnox(&e, secret_name))?;

        // Get the secret string (not binary)
        result
            .secret_string()
            .ok_or_else(|| FnoxError::ProviderInvalidResponse {
                provider: "AWS Secrets Manager".to_string(),
                details: format!("Secret '{}' has no string value", secret_name),
                hint: "Binary secrets are not supported".to_string(),
                url: "https://fnox.jdx.dev/providers/aws-sm".to_string(),
            })
            .map(|s| s.to_string())
    }

    /// Create or update a secret in AWS Secrets Manager
    pub async fn put_secret(&self, secret_name: &str, secret_value: &str) -> Result<()> {
        let client = self.create_client().await?;

        // Try to update existing secret first
        match client
            .put_secret_value()
            .secret_id(secret_name)
            .secret_string(secret_value)
            .send()
            .await
        {
            Ok(_) => {
                tracing::debug!("Updated secret '{}' in AWS Secrets Manager", secret_name);
                Ok(())
            }
            Err(e) => {
                // If secret doesn't exist, create it
                if e.to_string().contains("ResourceNotFoundException") {
                    client
                        .create_secret()
                        .name(secret_name)
                        .secret_string(secret_value)
                        .send()
                        .await
                        .map_err(|e| aws_error_to_fnox(&e, secret_name))?;
                    tracing::debug!("Created secret '{}' in AWS Secrets Manager", secret_name);
                    Ok(())
                } else {
                    Err(aws_error_to_fnox(&e, secret_name))
                }
            }
        }
    }
}

#[async_trait]
impl crate::providers::Provider for AwsSecretsManagerProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let secret_name = self.get_secret_name(value);
        tracing::debug!(
            "Getting secret '{}' from AWS Secrets Manager in region '{}'",
            secret_name,
            self.region
        );

        self.get_secret_value(&secret_name).await
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        tracing::debug!(
            "Getting {} secrets from AWS Secrets Manager using batch API",
            secrets.len()
        );

        let mut results = HashMap::new();

        // AWS Secrets Manager BatchGetSecretValue supports up to 20 secrets per call
        // So we need to chunk the requests
        const BATCH_SIZE: usize = 20;

        let client = match self.create_client().await {
            Ok(c) => c,
            Err(e) => {
                // If we can't create client, return errors for all secrets
                for (key, _) in secrets {
                    results.insert(
                        key.clone(),
                        Err(FnoxError::ProviderAuthFailed {
                            provider: "AWS Secrets Manager".to_string(),
                            details: e.to_string(),
                            hint: "Run 'aws sso login' or check AWS credentials".to_string(),
                            url: "https://fnox.jdx.dev/providers/aws-sm".to_string(),
                        }),
                    );
                }
                return results;
            }
        };

        for chunk in secrets.chunks(BATCH_SIZE) {
            // Build mapping from secret ID to original key
            // This allows exact matching without false positives
            let mut secret_id_to_key: HashMap<String, String> = HashMap::new();
            let secret_ids: Vec<String> = chunk
                .iter()
                .map(|(key, value)| {
                    let secret_id = self.get_secret_name(value);
                    secret_id_to_key.insert(secret_id.clone(), key.clone());
                    secret_id
                })
                .collect();

            tracing::debug!(
                "Fetching batch of {} secrets from AWS Secrets Manager",
                secret_ids.len()
            );

            // Call BatchGetSecretValue
            match client
                .batch_get_secret_value()
                .set_secret_id_list(Some(secret_ids.clone()))
                .send()
                .await
            {
                Ok(response) => {
                    // Process successfully retrieved secrets
                    for secret in response.secret_values() {
                        // Use name field for matching (not ARN, which has random suffix)
                        let secret_name = if let Some(name) = secret.name() {
                            name.to_string()
                        } else if let Some(arn) = secret.arn() {
                            // Fallback: extract name from ARN if name field is missing
                            // ARN format: arn:aws:secretsmanager:region:account:secret:name-SUFFIX
                            // We need to match against the name we requested (without suffix)
                            extract_name_from_arn(arn)
                        } else {
                            tracing::warn!("Secret in batch response has no name or ARN");
                            continue;
                        };

                        // Find the matching key using exact name match
                        if let Some(key) = secret_id_to_key.get(&secret_name) {
                            if let Some(secret_string) = secret.secret_string() {
                                results.insert(key.clone(), Ok(secret_string.to_string()));
                            } else {
                                results.insert(
                                    key.clone(),
                                    Err(FnoxError::ProviderInvalidResponse {
                                        provider: "AWS Secrets Manager".to_string(),
                                        details: format!(
                                            "Secret '{}' has no string value",
                                            secret_name
                                        ),
                                        hint: "Binary secrets are not supported".to_string(),
                                        url: "https://fnox.jdx.dev/providers/aws-sm".to_string(),
                                    }),
                                );
                            }
                        } else {
                            tracing::warn!(
                                "Received secret '{}' that was not requested in batch",
                                secret_name
                            );
                        }
                    }

                    // Handle errors for secrets that weren't retrieved
                    for error in response.errors() {
                        if let Some(error_secret_id) = error.secret_id() {
                            // Try exact match first, then check if it's an ARN
                            let lookup_name = if secret_id_to_key.contains_key(error_secret_id) {
                                error_secret_id.to_string()
                            } else {
                                // Might be an ARN in the error response
                                extract_name_from_arn(error_secret_id)
                            };

                            if let Some(key) = secret_id_to_key.get(&lookup_name) {
                                let error_msg =
                                    error.message().unwrap_or("Unknown error").to_string();
                                results.insert(
                                    key.clone(),
                                    Err(FnoxError::ProviderApiError {
                                        provider: "AWS Secrets Manager".to_string(),
                                        details: format!(
                                            "Failed to get '{}': {}",
                                            lookup_name, error_msg
                                        ),
                                        hint: "Check that the secret exists and you have access"
                                            .to_string(),
                                        url: "https://fnox.jdx.dev/providers/aws-sm".to_string(),
                                    }),
                                );
                            }
                        }
                    }

                    // Check for any secrets that weren't in response (neither success nor error)
                    for (secret_id, key) in &secret_id_to_key {
                        if !results.contains_key(key) {
                            results.insert(
                                key.clone(),
                                Err(FnoxError::ProviderSecretNotFound {
                                    provider: "AWS Secrets Manager".to_string(),
                                    secret: secret_id.clone(),
                                    hint: "Check that the secret exists".to_string(),
                                    url: "https://fnox.jdx.dev/providers/aws-sm".to_string(),
                                }),
                            );
                        }
                    }
                }
                Err(e) => {
                    // Batch call failed entirely, return errors for all secrets in this chunk
                    for (secret_id, key) in &secret_id_to_key {
                        results.insert(key.clone(), Err(aws_error_to_fnox(&e, secret_id)));
                    }
                }
            }
        }

        results
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client().await?;

        // Try to list secrets to verify connection
        client
            .list_secrets()
            .max_results(1)
            .send()
            .await
            .map_err(|e| aws_error_to_fnox(&e, "connection-test"))?;

        Ok(())
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let secret_name = self.get_secret_name(key);
        self.put_secret(&secret_name, value).await?;
        // Return the key name (without prefix) to store in config
        Ok(key.to_string())
    }
}
