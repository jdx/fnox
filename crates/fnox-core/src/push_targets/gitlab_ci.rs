//! GitLab CI/CD variables, set with `glab variable set`.
//!
//! `glab variable set` creates a variable and `glab variable update` changes
//! an existing one; both read the value from stdin. Neither documents an
//! upsert, so fnox tries `set` and falls back to `update`.

use super::PushTarget;
use super::cli::{Cli, opt};
use crate::error::Result;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const CLI: Cli = Cli {
    target_type: "gitlab-ci",
    program: "glab",
    install_hint: "mise use -g glab (or see https://gitlab.com/gitlab-org/cli)",
    hint: "Check that `glab auth status` succeeds and that you are a maintainer of the project or group",
};

/// How GitLab exposes a variable to jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VariableType {
    /// An environment variable holding the value
    EnvVar,
    /// An environment variable holding the path of a file with the value
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitlabCi {
    /// Project as `group/name` (default: the project `glab` detects from the
    /// current directory)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Group to set the variable in, instead of a project
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Environment scope of the variable (default: all environments)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Hide the value in job logs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    /// Expose the variable only to protected branches and tags
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,
    /// Do not expand `$` references in the value
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<bool>,
    /// Whether jobs get the value itself or a file path (default: env_var)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable_type: Option<VariableType>,
    /// Description shown in GitLab
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl GitlabCi {
    fn args(&self, command: &str, name: &str) -> Vec<String> {
        let mut args = vec![
            "variable".to_string(),
            command.to_string(),
            name.to_string(),
        ];
        opt(&mut args, "--repo", self.repo.as_deref());
        opt(&mut args, "--group", self.group.as_deref());
        opt(&mut args, "--scope", self.environment.as_deref());
        // Pass booleans explicitly so an update also turns them off
        for (flag, value) in [
            ("--masked", self.masked),
            ("--protected", self.protected),
            ("--raw", self.raw),
        ] {
            if let Some(value) = value {
                args.push(format!("{flag}={value}"));
            }
        }
        let variable_type = self.variable_type.map(|t| match t {
            VariableType::EnvVar => "env_var",
            VariableType::File => "file",
        });
        opt(&mut args, "--type", variable_type);
        opt(&mut args, "--description", self.description.as_deref());
        args
    }
}

#[async_trait]
impl PushTarget for GitlabCi {
    fn describe(&self) -> String {
        let place = match (&self.group, &self.repo) {
            (Some(group), _) => format!("group {group}"),
            (None, Some(repo)) => repo.clone(),
            (None, None) => "the current project".to_string(),
        };
        match &self.environment {
            Some(env) => format!("GitLab CI/CD variable in {place}, environment {env}"),
            None => format!("GitLab CI/CD variable in {place}"),
        }
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.group.is_some() && self.repo.is_some() {
            return Err("set either group or repo, not both".into());
        }
        if self.group.is_some() && self.environment.is_some() {
            return Err("glab cannot scope a group variable to an environment".into());
        }
        Ok(())
    }

    async fn push(&self, name: &str, value: &str) -> Result<()> {
        let set_error = match CLI.try_run(&self.args("set", name), value).await? {
            Ok(()) => return Ok(()),
            Err(stderr) => stderr,
        };
        // Most likely the variable exists already
        match CLI.try_run(&self.args("update", name), value).await? {
            Ok(()) => Ok(()),
            Err(update_error) => Err(CLI.failed(format!(
                "glab variable set failed: {set_error}; glab variable update failed: {update_error}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> GitlabCi {
        toml_edit::de::from_str(toml).unwrap()
    }

    #[test]
    fn args_pass_booleans_explicitly() {
        let t = parse(
            "repo = \"acme/api\"\nenvironment = \"production\"\nmasked = true\nprotected = false\nvariable_type = \"file\"",
        );
        assert_eq!(
            t.args("update", "KEY"),
            [
                "variable",
                "update",
                "KEY",
                "--repo",
                "acme/api",
                "--scope",
                "production",
                "--masked=true",
                "--protected=false",
                "--type",
                "file"
            ]
        );
        assert_eq!(
            t.describe(),
            "GitLab CI/CD variable in acme/api, environment production"
        );
    }

    #[test]
    fn rejects_conflicting_scopes() {
        assert!(
            parse("group = \"acme\"\nrepo = \"acme/api\"")
                .validate()
                .is_err()
        );
        assert!(
            parse("group = \"acme\"\nenvironment = \"prod\"")
                .validate()
                .is_err()
        );
        assert!(parse("group = \"acme\"").validate().is_ok());
    }
}
