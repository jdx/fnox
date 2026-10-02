use crate::error::Result;
use crate::pulumi_esc_api::{self, EscEnv, PROVIDER_NAME};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;

const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/pulumi-esc";

/// Duration to request when opening an environment for a secret read. The
/// session is only used within this request; 60s is a generous ceiling.
const OPEN_DURATION: Duration = Duration::from_secs(60);

pub struct PulumiEscProvider {
    env: EscEnv,
}

impl PulumiEscProvider {
    pub fn new(
        organization: String,
        project: Option<String>,
        environment: String,
        token: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            env: EscEnv {
                organization,
                project,
                environment,
                token,
            },
        })
    }

    async fn fetch_env(&self) -> Result<serde_json::Value> {
        self.env.open(OPEN_DURATION, PROVIDER_URL).await
    }
}

#[async_trait]
impl crate::providers::Provider for PulumiEscProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Pulumi ESC", value);
        let body = self.fetch_env().await?;
        pulumi_esc_api::lookup(&body, value, PROVIDER_URL)
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
                (
                    key.clone(),
                    pulumi_esc_api::lookup(&body, path, PROVIDER_URL),
                )
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
    pulumi_esc_api::ENV_VARS
}
