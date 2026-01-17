use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_ssm::Client;
use std::collections::HashMap;

/// Helper function to extract detailed error information from AWS SDK errors
fn format_aws_error<E, R>(err: &aws_sdk_ssm::error::SdkError<E, R>) -> String
where
    E: std::fmt::Debug + std::fmt::Display,
    R: std::fmt::Debug,
{
    use aws_sdk_ssm::error::SdkError;

    match err {
        SdkError::ServiceError(service_err) => {
            // Extract service-specific error details
            format!("{}", service_err.err())
        }
        SdkError::TimeoutError(timeout_err) => {
            format!("Request timed out: {:?}", timeout_err)
        }
        SdkError::DispatchFailure(dispatch_err) => {
            // Unwrap dispatch failure to show underlying cause
            if let Some(connector_err) = dispatch_err.as_connector_error() {
                // Walk the error chain to find root cause
                let mut error_chain = vec![connector_err.to_string()];
                let mut source = std::error::Error::source(connector_err);
                while let Some(err) = source {
                    error_chain.push(err.to_string());
                    source = std::error::Error::source(err);
                }

                // Build a detailed error message with the full chain
                let full_error = error_chain.join(": ");

                // Add helpful context based on common error patterns
                let context = if full_error.contains("dns error")
                    || full_error.contains("failed to lookup address")
                {
                    " (DNS resolution failed - check network connectivity and AWS region endpoint)"
                } else if full_error.contains("connection refused") {
                    " (Connection refused - check if AWS endpoint is accessible and firewall rules)"
                } else if full_error.contains("tls")
                    || full_error.contains("ssl")
                    || full_error.contains("certificate")
                {
                    " (TLS/SSL error - check system certificates or network proxy configuration)"
                } else if full_error.contains("timeout") {
                    " (Connection timeout - check network connectivity and firewall rules)"
                } else if full_error.contains("No credentials")
                    || full_error.contains("Unable to load credentials")
                {
                    " (AWS credentials not found or invalid - check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, or AWS profile)"
                } else {
                    ""
                };

                format!("{}{}", full_error, context)
            } else {
                format!("Dispatch failure: {:?}", dispatch_err)
            }
        }
        SdkError::ConstructionFailure(construction_err) => {
            format!("Request construction failed: {:?}", construction_err)
        }
        SdkError::ResponseError(response_err) => {
            format!("Response error: {:?}", response_err)
        }
        _ => format!("{}", err),
    }
}

pub struct AwsParameterStoreProvider {
    region: String,
    prefix: Option<String>,
}

impl AwsParameterStoreProvider {
    pub fn new(region: String, prefix: Option<String>) -> Self {
        Self { region, prefix }
    }

    pub fn get_parameter_name(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}{}", prefix, key),
            None => key.to_string(),
        }
    }

    /// Create an AWS SSM client
    async fn create_client(&self) -> Result<Client> {
        // Load AWS config with the specified region
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_ssm::config::Region::new(self.region.clone()))
            .load()
            .await;

        Ok(Client::new(&config))
    }

    /// Get a parameter value from AWS Systems Manager Parameter Store
    async fn get_parameter_value(&self, parameter_name: &str) -> Result<String> {
        let client = self.create_client().await?;

        let result = client
            .get_parameter()
            .name(parameter_name)
            .with_decryption(true) // Automatically decrypt SecureString parameters
            .send()
            .await
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to get parameter '{}' from AWS Parameter Store: {}",
                    parameter_name,
                    format_aws_error(&e)
                ))
            })?;

        // Get the parameter value
        result
            .parameter()
            .and_then(|p| p.value())
            .ok_or_else(|| {
                FnoxError::Provider(format!("Parameter '{}' has no value", parameter_name))
            })
            .map(|s| s.to_string())
    }

    /// Fetch a batch of parameters (up to 10) from AWS Parameter Store
    async fn fetch_batch(
        &self,
        client: &Client,
        chunk: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        // Build mapping from parameter name to original keys (multiple keys can share same param)
        let mut param_name_to_keys: HashMap<String, Vec<String>> = HashMap::new();
        let mut param_names: Vec<String> = Vec::new();
        for (key, value) in chunk {
            let param_name = self.get_parameter_name(value);
            param_name_to_keys
                .entry(param_name.clone())
                .or_default()
                .push(key.clone());
            // Only add unique parameter names to the request
            if !param_names.contains(&param_name) {
                param_names.push(param_name);
            }
        }

        let mut results = HashMap::new();
        tracing::debug!(
            "Fetching batch of {} parameters from AWS Parameter Store",
            param_names.len()
        );

        // Call GetParameters
        match client
            .get_parameters()
            .set_names(Some(param_names.clone()))
            .with_decryption(true)
            .send()
            .await
        {
            Ok(response) => {
                // Process successfully retrieved parameters
                for parameter in response.parameters() {
                    if let Some(name) = parameter.name()
                        && let Some(keys) = param_name_to_keys.get(name)
                    {
                        // Insert result for all keys that reference this parameter
                        for key in keys {
                            if let Some(value) = parameter.value() {
                                results.insert(key.clone(), Ok(value.to_string()));
                            } else {
                                results.insert(
                                    key.clone(),
                                    Err(FnoxError::Provider(format!(
                                        "Parameter '{}' has no value",
                                        name
                                    ))),
                                );
                            }
                        }
                    }
                }

                // Handle invalid parameters (not found)
                for invalid_param in response.invalid_parameters() {
                    if let Some(keys) = param_name_to_keys.get(invalid_param) {
                        for key in keys {
                            results.insert(
                                key.clone(),
                                Err(FnoxError::Provider(format!(
                                    "Parameter '{}' not found in AWS Parameter Store",
                                    invalid_param
                                ))),
                            );
                        }
                    }
                }

                // Check for any keys that weren't in response
                for (param_name, keys) in &param_name_to_keys {
                    for key in keys {
                        if !results.contains_key(key) {
                            results.insert(
                                key.clone(),
                                Err(FnoxError::Provider(format!(
                                    "Parameter '{}' not found in batch response",
                                    param_name
                                ))),
                            );
                        }
                    }
                }
            }
            Err(e) => {
                // Batch call failed entirely, return errors for all keys in this chunk
                let error_msg = format!(
                    "AWS Parameter Store batch call failed: {}",
                    format_aws_error(&e)
                );
                for keys in param_name_to_keys.values() {
                    for key in keys {
                        results.insert(key.clone(), Err(FnoxError::Provider(error_msg.clone())));
                    }
                }
            }
        }

        results
    }

    /// Create or update a parameter in AWS Systems Manager Parameter Store
    pub async fn put_parameter(&self, parameter_name: &str, parameter_value: &str) -> Result<()> {
        let client = self.create_client().await?;

        client
            .put_parameter()
            .name(parameter_name)
            .value(parameter_value)
            .r#type(aws_sdk_ssm::types::ParameterType::SecureString)
            .overwrite(true) // Overwrite if exists
            .send()
            .await
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to put parameter '{}' in AWS Parameter Store: {}",
                    parameter_name,
                    format_aws_error(&e)
                ))
            })?;

        tracing::debug!(
            "Stored parameter '{}' in AWS Parameter Store",
            parameter_name
        );
        Ok(())
    }
}

#[async_trait]
impl crate::providers::Provider for AwsParameterStoreProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let parameter_name = self.get_parameter_name(value);
        tracing::debug!(
            "Getting parameter '{}' from AWS Parameter Store in region '{}'",
            parameter_name,
            self.region
        );

        self.get_parameter_value(&parameter_name).await
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        use futures::stream::{self, StreamExt};

        tracing::debug!(
            "Getting {} parameters from AWS Parameter Store using batch API",
            secrets.len()
        );

        // AWS SSM GetParameters supports up to 10 parameters per call
        const BATCH_SIZE: usize = 10;

        let client = match self.create_client().await {
            Ok(c) => c,
            Err(e) => {
                // If we can't create client, return errors for all secrets
                let error_msg = format!("Failed to create AWS client: {}", e);
                return secrets
                    .iter()
                    .map(|(key, _)| (key.clone(), Err(FnoxError::Provider(error_msg.clone()))))
                    .collect();
            }
        };

        // Process chunks concurrently (up to 10 concurrent batches)
        let chunks: Vec<_> = secrets.chunks(BATCH_SIZE).map(|c| c.to_vec()).collect();
        let chunk_results: Vec<_> = stream::iter(chunks)
            .map(|chunk| {
                let client = &client;
                async move { self.fetch_batch(client, &chunk).await }
            })
            .buffer_unordered(10)
            .collect()
            .await;

        // Merge all chunk results into a single HashMap
        chunk_results.into_iter().flatten().collect()
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.create_client().await?;

        // Try to describe parameters to verify connection
        client
            .describe_parameters()
            .max_results(1)
            .send()
            .await
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to connect to AWS Parameter Store in region '{}': {}",
                    self.region,
                    format_aws_error(&e)
                ))
            })?;

        Ok(())
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let parameter_name = self.get_parameter_name(key);
        self.put_parameter(&parameter_name, value).await?;
        // Return the key name (without prefix) to store in config
        Ok(key.to_string())
    }
}
