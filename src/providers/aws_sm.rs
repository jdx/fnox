use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client;
use std::collections::HashMap;
use std::path::Path;

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
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to get secret '{}' from AWS Secrets Manager: {}",
                    secret_name, e
                ))
            })?;

        // Get the secret string (not binary)
        result
            .secret_string()
            .ok_or_else(|| {
                FnoxError::Provider(format!(
                    "Secret '{}' has no string value (binary secrets not supported)",
                    secret_name
                ))
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
                        .map_err(|e| {
                            FnoxError::Provider(format!(
                                "Failed to create secret '{}' in AWS Secrets Manager: {}",
                                secret_name, e
                            ))
                        })?;
                    tracing::debug!("Created secret '{}' in AWS Secrets Manager", secret_name);
                    Ok(())
                } else {
                    Err(FnoxError::Provider(format!(
                        "Failed to update secret '{}' in AWS Secrets Manager: {}",
                        secret_name, e
                    )))
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

    async fn get_secret(&self, value: &str, _key_file: Option<&Path>) -> Result<String> {
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
        _key_file: Option<&Path>,
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
                let error_msg = format!("Failed to create AWS client: {}", e);
                for (key, _) in secrets {
                    results.insert(key.clone(), Err(FnoxError::Provider(error_msg.clone())));
                }
                return results;
            }
        };

        for chunk in secrets.chunks(BATCH_SIZE) {
            // Build list of secret IDs to fetch
            let secret_ids: Vec<String> = chunk
                .iter()
                .map(|(_, value)| self.get_secret_name(value))
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
                        // Find which key this secret corresponds to
                        if let Some(arn_or_name) = secret.arn().or(secret.name()) {
                            // Match back to original key
                            for (key, value) in chunk {
                                let expected_name = self.get_secret_name(value);
                                if arn_or_name.ends_with(&expected_name)
                                    || arn_or_name == expected_name
                                {
                                    if let Some(secret_string) = secret.secret_string() {
                                        results.insert(key.clone(), Ok(secret_string.to_string()));
                                    } else {
                                        results.insert(
                                            key.clone(),
                                            Err(FnoxError::Provider(format!(
                                                "Secret '{}' has no string value (binary secrets not supported)",
                                                expected_name
                                            ))),
                                        );
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    // Handle errors for secrets that weren't retrieved
                    for error in response.errors() {
                        if let Some(error_secret_id) = error.secret_id() {
                            // Match back to original key
                            for (key, value) in chunk {
                                let expected_name = self.get_secret_name(value);
                                if error_secret_id.ends_with(&expected_name)
                                    || error_secret_id == expected_name
                                {
                                    let error_msg =
                                        error.message().unwrap_or("Unknown error").to_string();
                                    results.insert(
                                        key.clone(),
                                        Err(FnoxError::Provider(format!(
                                            "Failed to get secret '{}': {}",
                                            expected_name, error_msg
                                        ))),
                                    );
                                    break;
                                }
                            }
                        }
                    }

                    // Check for any secrets that weren't in response (neither success nor error)
                    for (key, value) in chunk {
                        if !results.contains_key(key) {
                            let secret_name = self.get_secret_name(value);
                            results.insert(
                                key.clone(),
                                Err(FnoxError::Provider(format!(
                                    "Secret '{}' not found in batch response",
                                    secret_name
                                ))),
                            );
                        }
                    }
                }
                Err(e) => {
                    // Batch call failed entirely, return errors for all secrets in this chunk
                    let error_msg = format!("AWS Secrets Manager batch call failed: {}", e);
                    for (key, _) in chunk {
                        results.insert(key.clone(), Err(FnoxError::Provider(error_msg.clone())));
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
            .map_err(|e| {
                FnoxError::Provider(format!(
                    "Failed to connect to AWS Secrets Manager in region '{}': {}",
                    self.region, e
                ))
            })?;

        Ok(())
    }
}
