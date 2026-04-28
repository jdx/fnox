use crate::error::{FnoxError, Result};
use crate::pulumi_esc_api::{self, EscClient};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;

const PROVIDER_NAME: &str = "Pulumi ESC";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/pulumi-esc";

/// Duration to request when opening an environment for a secret read. The
/// session is only used within this request; 60s is a generous ceiling.
const OPEN_DURATION: Duration = Duration::from_secs(60);

pub struct PulumiEscProvider {
    organization: String,
    project: Option<String>,
    environment: String,
    token: Option<String>,
}

impl PulumiEscProvider {
    pub fn new(
        organization: String,
        project: Option<String>,
        environment: String,
        token: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            organization,
            project,
            environment,
            token,
        })
    }

    fn env_ref(&self) -> String {
        pulumi_esc_api::build_env_ref(
            &self.organization,
            self.project.as_deref(),
            &self.environment,
        )
    }

    fn client(&self) -> Result<EscClient> {
        EscClient::new(self.token.as_deref(), PROVIDER_URL)
    }

    async fn fetch_env(&self) -> Result<serde_json::Value> {
        self.client()?
            .open_and_read(&self.env_ref(), OPEN_DURATION)
            .await
    }
}

#[async_trait]
impl crate::providers::Provider for PulumiEscProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Pulumi ESC", value);
        let body = self.fetch_env().await?;
        pulumi_esc_api::lookup(&body, value).ok_or_else(|| FnoxError::ProviderSecretNotFound {
            provider: PROVIDER_NAME.to_string(),
            secret: value.to_string(),
            hint: "Check that the path exists in your Pulumi ESC environment".to_string(),
            url: PROVIDER_URL.to_string(),
        })
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        if secrets.is_empty() {
            return HashMap::new();
        }

        tracing::debug!("Batch fetching {} secrets from Pulumi ESC", secrets.len());

        let body = match self.fetch_env().await {
            Ok(b) => b,
            Err(e) => {
                return secrets
                    .iter()
                    .map(|(k, name)| {
                        (
                            k.clone(),
                            Err(e.map_batch_error(
                                name,
                                PROVIDER_NAME,
                                "Check your Pulumi ESC configuration",
                                PROVIDER_URL,
                            )),
                        )
                    })
                    .collect();
            }
        };

        secrets
            .iter()
            .map(|(key, path)| {
                let result = pulumi_esc_api::lookup(&body, path).ok_or_else(|| {
                    FnoxError::ProviderSecretNotFound {
                        provider: PROVIDER_NAME.to_string(),
                        secret: path.clone(),
                        hint: "Check that the path exists in your Pulumi ESC environment"
                            .to_string(),
                        url: PROVIDER_URL.to_string(),
                    }
                });
                (key.clone(), result)
            })
            .collect()
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Pulumi ESC");
        self.fetch_env().await?;
        tracing::debug!("Pulumi ESC connection test successful");
        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &["PULUMI_ACCESS_TOKEN", "FNOX_PULUMI_ACCESS_TOKEN"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ref_with_project() {
        let p = PulumiEscProvider::new("myorg".into(), Some("myproj".into()), "dev".into(), None)
            .unwrap();
        assert_eq!(p.env_ref(), "myorg/myproj/dev");
    }

    #[test]
    fn env_ref_without_project() {
        let p = PulumiEscProvider::new("myorg".into(), None, "dev".into(), None).unwrap();
        assert_eq!(p.env_ref(), "myorg/dev");
    }
}
