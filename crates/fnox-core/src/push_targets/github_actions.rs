//! GitHub Actions secrets, set with `gh secret set`.
//!
//! `gh` reads the value from stdin and handles GitHub's sealed-box encryption
//! and authentication.

use super::PushTarget;
use super::cli::{Cli, opt};
use crate::error::Result;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const CLI: Cli = Cli {
    target_type: "github-actions",
    program: "gh",
    install_hint: "mise use -g gh (or see https://cli.github.com)",
    hint: "Check that `gh auth status` succeeds and that you can manage secrets there",
};

/// Which repositories can use an organization secret
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    All,
    Private,
    Selected,
}

/// Which GitHub feature a secret is for
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum App {
    Actions,
    Dependabot,
    Codespaces,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GithubActions {
    /// Repository as `owner/name` (default: the repository `gh` detects from
    /// the current directory)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Deployment environment to set the secret in, instead of the repository
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Organization to set the secret in, instead of a repository
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// Which repositories can use an organization secret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    /// Repositories that can use an organization secret with
    /// `visibility = "selected"`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
    /// Which GitHub feature the secret is for (default: actions)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<App>,
}

impl GithubActions {
    fn args(&self, name: &str) -> Vec<String> {
        let mut args = vec!["secret".to_string(), "set".to_string(), name.to_string()];
        opt(&mut args, "--org", self.org.as_deref());
        opt(&mut args, "--repo", self.repo.as_deref());
        opt(&mut args, "--env", self.environment.as_deref());
        let visibility = self.visibility.map(|v| match v {
            Visibility::All => "all",
            Visibility::Private => "private",
            Visibility::Selected => "selected",
        });
        opt(&mut args, "--visibility", visibility);
        if !self.repos.is_empty() {
            opt(&mut args, "--repos", Some(&self.repos.join(",")));
        }
        let app = self.app.map(|app| match app {
            App::Actions => "actions",
            App::Dependabot => "dependabot",
            App::Codespaces => "codespaces",
        });
        opt(&mut args, "--app", app);
        args
    }
}

#[async_trait]
impl PushTarget for GithubActions {
    fn describe(&self) -> String {
        let kind = match self.app {
            Some(App::Dependabot) => "Dependabot secret",
            Some(App::Codespaces) => "Codespaces secret",
            _ => "GitHub Actions secret",
        };
        let place = match (&self.org, &self.repo) {
            (Some(org), _) => format!("organization {org}"),
            (None, Some(repo)) => repo.clone(),
            (None, None) => "the current repository".to_string(),
        };
        match &self.environment {
            Some(env) => format!("{kind} in {place}, environment {env}"),
            None => format!("{kind} in {place}"),
        }
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.org.is_some() && (self.repo.is_some() || self.environment.is_some()) {
            return Err("set either org, or repo and environment, not both".into());
        }
        if self.org.is_none() && (self.visibility.is_some() || !self.repos.is_empty()) {
            return Err("visibility and repos apply only to an org secret".into());
        }
        if !self.repos.is_empty() && self.visibility != Some(Visibility::Selected) {
            return Err("repos requires visibility = \"selected\"".into());
        }
        if self.environment.is_some() && self.app.is_some_and(|app| app != App::Actions) {
            return Err("environment secrets exist only for app = \"actions\"".into());
        }
        Ok(())
    }

    fn validate_name(&self, name: &str) -> std::result::Result<(), String> {
        // GitHub reserves the prefix, in any case
        if name.to_ascii_uppercase().starts_with("GITHUB_") {
            return Err("GitHub secret names cannot start with GITHUB_".into());
        }
        Ok(())
    }

    async fn push(&self, name: &str, value: &str) -> Result<()> {
        // Without --body, gh reads the value from stdin until EOF
        CLI.run(&self.args(name), value).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> GithubActions {
        toml_edit::de::from_str(toml).unwrap()
    }

    #[test]
    fn repo_environment_args() {
        let t = parse("repo = \"jdx/fnox\"\nenvironment = \"production\"");
        assert_eq!(
            t.args("KEY"),
            [
                "secret",
                "set",
                "KEY",
                "--repo",
                "jdx/fnox",
                "--env",
                "production"
            ]
        );
        assert_eq!(
            t.describe(),
            "GitHub Actions secret in jdx/fnox, environment production"
        );
    }

    #[test]
    fn org_selected_args() {
        let t = parse(
            "org = \"jdx\"\nvisibility = \"selected\"\nrepos = [\"fnox\", \"mise\"]\napp = \"dependabot\"",
        );
        assert!(t.validate().is_ok());
        assert_eq!(
            t.args("KEY")[3..],
            [
                "--org",
                "jdx",
                "--visibility",
                "selected",
                "--repos",
                "fnox,mise",
                "--app",
                "dependabot"
            ]
        );
        assert_eq!(t.describe(), "Dependabot secret in organization jdx");
    }

    #[test]
    fn rejects_conflicting_scopes() {
        for toml in [
            "repo = \"jdx/fnox\"\norg = \"jdx\"",
            "repo = \"jdx/fnox\"\nvisibility = \"all\"",
            "org = \"jdx\"\nvisibility = \"all\"\nrepos = [\"x\"]",
            "environment = \"prod\"\napp = \"codespaces\"",
        ] {
            assert!(parse(toml).validate().is_err(), "{toml}");
        }
    }

    #[test]
    fn rejects_reserved_names() {
        let t = parse("");
        assert!(t.validate_name("GITHUB_TOKEN").is_err());
        assert!(t.validate_name("github_token").is_err());
        assert!(t.validate_name("MY_GITHUB_TOKEN").is_ok());
    }

    #[test]
    fn defaults_to_current_repository() {
        assert_eq!(
            parse("").describe(),
            "GitHub Actions secret in the current repository"
        );
    }
}
