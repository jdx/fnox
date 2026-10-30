//! Cloudflare Workers secrets, set with `wrangler secret put`.
//!
//! `wrangler secret put` reads the value from stdin, replaces an existing
//! secret, and deploys a new version of the Worker.

use super::PushTarget;
use super::cli::{Cli, opt};
use crate::error::Result;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const CLI: Cli = Cli {
    target_type: "cloudflare-workers",
    program: "wrangler",
    install_hint: "mise use -g npm:wrangler (or see https://developers.cloudflare.com/workers/wrangler/install-and-update/)",
    hint: "Check that `wrangler whoami` succeeds and that the Worker exists",
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloudflareWorkers {
    /// Worker name (default: the name in the Wrangler config of the current
    /// directory)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<String>,
    /// Wrangler environment to set the secret in
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

impl CloudflareWorkers {
    fn args(&self, name: &str) -> Vec<String> {
        let mut args = vec!["secret".to_string(), "put".to_string(), name.to_string()];
        opt(&mut args, "--name", self.worker.as_deref());
        opt(&mut args, "--env", self.environment.as_deref());
        args
    }
}

#[async_trait]
impl PushTarget for CloudflareWorkers {
    fn describe(&self) -> String {
        let worker = match &self.worker {
            Some(worker) => format!("Worker {worker}"),
            None => "the Worker in the current directory".to_string(),
        };
        match &self.environment {
            Some(env) => format!("Cloudflare Workers secret in {worker}, environment {env}"),
            None => format!("Cloudflare Workers secret in {worker}"),
        }
    }

    async fn push(&self, name: &str, value: &str) -> Result<()> {
        CLI.run(&self.args(name), value).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_and_description() {
        let t: CloudflareWorkers =
            toml_edit::de::from_str("worker = \"api\"\nenvironment = \"staging\"").unwrap();
        assert_eq!(
            t.args("KEY"),
            ["secret", "put", "KEY", "--name", "api", "--env", "staging"]
        );
        assert_eq!(
            t.describe(),
            "Cloudflare Workers secret in Worker api, environment staging"
        );
    }
}
