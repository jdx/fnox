//! Push targets: write-only secret stores that fnox copies values into.
//!
//! A target, such as GitHub Actions secrets, accepts a value but never returns
//! it, so it cannot be a provider. fnox stays the source of truth and
//! `fnox push` copies each secret's resolved value to the targets listed in its
//! `push` field.
//!
//! Each target type is one config struct that implements [`PushTarget`]. Every
//! type is documented in `docs/targets/<type>.md`; a test checks that each
//! config field appears there.

use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

mod cli;
pub mod cloudflare_workers;
pub mod fly;
pub mod forgejo_actions;
pub mod github_actions;
pub mod gitlab_ci;
pub mod hcp_terraform;
pub mod vercel;

/// A write-only destination for secret values
#[async_trait]
pub trait PushTarget: Send + Sync {
    /// Where a pushed value ends up, for confirmation prompts and dry runs
    fn describe(&self) -> String;

    /// Reject a config that cannot work, before anything is pushed. Returns a
    /// message that the caller prefixes with the target name.
    fn validate(&self) -> std::result::Result<(), String> {
        Ok(())
    }

    /// Store `value` under `name`, replacing any existing value
    async fn push(&self, name: &str, value: &str) -> Result<()>;
}

/// Configuration for a push target
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum PushTargetConfig {
    /// Cloudflare Workers secrets, set with `wrangler secret put`
    CloudflareWorkers(cloudflare_workers::CloudflareWorkers),
    /// Fly.io app secrets, set with `fly secrets import`
    Fly(fly::Fly),
    /// Forgejo or Gitea Actions secrets, set through the REST API
    ForgejoActions(forgejo_actions::ForgejoActions),
    /// GitHub Actions, Dependabot or Codespaces secrets, set with `gh secret set`
    GithubActions(github_actions::GithubActions),
    /// GitLab CI/CD variables, set with `glab variable set`
    GitlabCi(gitlab_ci::GitlabCi),
    /// HCP Terraform or Terraform Enterprise workspace variables, set through
    /// the REST API
    HcpTerraform(hcp_terraform::HcpTerraform),
    /// Vercel environment variables, set with `vercel env add`
    Vercel(vercel::Vercel),
}

impl PushTargetConfig {
    /// The target implementation for this config
    pub fn target(&self) -> &dyn PushTarget {
        match self {
            Self::CloudflareWorkers(t) => t,
            Self::Fly(t) => t,
            Self::ForgejoActions(t) => t,
            Self::GithubActions(t) => t,
            Self::GitlabCi(t) => t,
            Self::HcpTerraform(t) => t,
            Self::Vercel(t) => t,
        }
    }

    /// Check the config of the target named `name`
    pub fn validate(&self, name: &str) -> Result<()> {
        self.target()
            .validate()
            .map_err(|msg| FnoxError::Config(format!("push target '{name}': {msg}")))
    }
}

/// Documentation URL for a target type
fn docs_url(target_type: &str) -> String {
    format!("https://fnox.jdx.dev/targets/{target_type}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Every target type has a page in docs/targets/ that mentions each of its
    /// config fields, so the docs cannot fall behind the schema.
    #[test]
    fn every_target_field_is_documented() {
        let schema = serde_json::to_value(schemars::schema_for!(PushTargetConfig)).unwrap();
        let docs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/targets");
        let variants = schema["oneOf"].as_array().expect("tagged enum schema");
        assert!(!variants.is_empty());
        let overview = std::fs::read_to_string(docs.join("index.md")).unwrap();
        for variant in variants {
            let variant = resolve(&schema, variant);
            let properties = variant["properties"].as_object().unwrap();
            let target_type = properties["type"]["const"]
                .as_str()
                .or_else(|| properties["type"]["enum"][0].as_str())
                .unwrap();
            let path = docs.join(format!("{target_type}.md"));
            let page = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("missing docs page {}", path.display()));
            for field in properties.keys().filter(|k| *k != "type") {
                assert!(
                    page.contains(&format!("`{field}`")),
                    "{} does not document `{field}`",
                    path.display()
                );
            }
            assert!(
                overview.contains(&format!("/targets/{target_type})")),
                "docs/targets/index.md does not link {target_type}"
            );
        }
    }

    fn resolve<'a>(root: &'a serde_json::Value, v: &'a serde_json::Value) -> &'a serde_json::Value {
        match v.get("$ref").and_then(|r| r.as_str()) {
            Some(r) => {
                let name = r.rsplit('/').next().unwrap();
                root.get("$defs")
                    .or_else(|| root.get("definitions"))
                    .and_then(|d| d.get(name))
                    .unwrap()
            }
            None => v,
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = toml_edit::de::from_str::<PushTargetConfig>(
            "type = \"fly\"\napp = \"x\"\nrepo = \"y\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("repo"), "{err}");
    }
}
