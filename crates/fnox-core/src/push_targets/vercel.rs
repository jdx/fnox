//! Vercel environment variables, set with `vercel env add`.
//!
//! `vercel env add` reads the value from stdin, and `--force` replaces an
//! existing variable for the same environment.

use super::PushTarget;
use super::cli::{Cli, opt};
use crate::error::Result;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const CLI: Cli = Cli {
    target_type: "vercel",
    program: "vercel",
    install_hint: "mise use -g npm:vercel (or see https://vercel.com/docs/cli)",
    hint: "Run fnox push in a directory linked with `vercel link`, and check `vercel whoami`",
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vercel {
    /// Environments to set the variable in: `production`, `preview`,
    /// `development`, or a custom environment
    pub environments: Vec<String>,
    /// Git branch for a `preview` variable (default: all preview branches)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    /// Store the value as sensitive, so it cannot be read back
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    /// Team that owns the project (default: the team of the linked project)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl Vercel {
    fn args(&self, name: &str, environment: &str) -> Vec<String> {
        let mut args = vec![
            "env".to_string(),
            "add".to_string(),
            name.to_string(),
            environment.to_string(),
        ];
        if let Some(branch) = &self.git_branch {
            args.push(branch.clone());
        }
        args.extend(["--force".to_string(), "--yes".to_string()]);
        match self.sensitive {
            Some(true) => args.push("--sensitive".to_string()),
            Some(false) => args.push("--no-sensitive".to_string()),
            None => {}
        }
        opt(&mut args, "--scope", self.scope.as_deref());
        args
    }
}

#[async_trait]
impl PushTarget for Vercel {
    fn describe(&self) -> String {
        let mut place = format!(
            "Vercel environment variable in {}",
            self.environments.join(", ")
        );
        if let Some(branch) = &self.git_branch {
            place.push_str(&format!(" (branch {branch})"));
        }
        if let Some(scope) = &self.scope {
            place.push_str(&format!(", team {scope}"));
        }
        place
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.environments.is_empty() {
            return Err("environments must list at least one environment".into());
        }
        if self.git_branch.is_some() && self.environments != ["preview"] {
            return Err("git_branch requires environments = [\"preview\"]".into());
        }
        Ok(())
    }

    async fn push(&self, name: &str, value: &str) -> Result<()> {
        for environment in &self.environments {
            CLI.run(&self.args(name, environment), value).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> Vercel {
        toml_edit::de::from_str(toml).unwrap()
    }

    #[test]
    fn args_force_and_sensitive() {
        let t = parse(
            "environments = [\"preview\"]\ngit_branch = \"main\"\nsensitive = true\nscope = \"acme\"",
        );
        assert!(t.validate().is_ok());
        assert_eq!(
            t.args("KEY", "preview"),
            [
                "env",
                "add",
                "KEY",
                "preview",
                "main",
                "--force",
                "--yes",
                "--sensitive",
                "--scope",
                "acme"
            ]
        );
        assert_eq!(
            t.describe(),
            "Vercel environment variable in preview (branch main), team acme"
        );
    }

    #[test]
    fn rejects_bad_environments() {
        assert!(parse("environments = []").validate().is_err());
        assert!(
            parse("environments = [\"production\"]\ngit_branch = \"main\"")
                .validate()
                .is_err()
        );
    }
}
