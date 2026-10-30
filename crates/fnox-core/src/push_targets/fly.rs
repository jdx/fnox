//! Fly.io app secrets, set with `fly secrets import`.
//!
//! `fly secrets import` reads `NAME=VALUE` lines from stdin. Its parser strips
//! `#` comments and surrounding quotes, so fnox wraps each value in `"""`,
//! which flyctl keeps verbatim, and refuses the few values that flyctl would
//! still change.

use super::PushTarget;
use super::cli::{Cli, opt};
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const CLI: Cli = Cli {
    target_type: "fly",
    program: "fly",
    install_hint: "mise use -g flyctl (or see https://fly.io/docs/flyctl/install/)",
    hint: "Check that `fly auth whoami` succeeds and that you can deploy the app",
};

/// flyctl reads lines with Go's bufio.Scanner, which stops at 64 KiB
const MAX_LINE: usize = 60 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fly {
    /// App name (default: the app in `fly.toml` in the current directory)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// Set the secret without redeploying the app's Machines
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stage: bool,
}

impl Fly {
    fn args(&self) -> Vec<String> {
        let mut args = vec!["secrets".to_string(), "import".to_string()];
        opt(&mut args, "--app", self.app.as_deref());
        if self.stage {
            args.push("--stage".to_string());
        }
        args
    }
}

/// The `NAME="""VALUE"""` line that `fly secrets import` reads back as exactly
/// `value`, or why there is none
fn import_line(name: &str, value: &str) -> std::result::Result<String, &'static str> {
    if value.contains('\r') {
        return Err("it contains a carriage return, which flyctl drops");
    }
    let lines: Vec<&str> = value.split('\n').collect();
    if lines.iter().any(|line| line.len() > MAX_LINE) {
        return Err("it has a line longer than flyctl reads");
    }
    // flyctl cuts the first line at `#` when the text before it holds an even
    // number of quotes; with the opening `"""` that means an odd number here
    if let Some((before, _)) = lines[0].split_once('#')
        && before.matches('"').count() % 2 == 1
    {
        return Err("flyctl would read the text after its '#' as a comment");
    }
    // A line ending in `"""` would close a multiline value early
    if lines[..lines.len() - 1]
        .iter()
        .any(|line| line.ends_with("\"\"\""))
    {
        return Err("a line ends in \"\"\", which flyctl reads as the end of the value");
    }
    Ok(format!("{name}=\"\"\"{value}\"\"\"\n"))
}

#[async_trait]
impl PushTarget for Fly {
    fn describe(&self) -> String {
        let app = match &self.app {
            Some(app) => format!("app {app}"),
            None => "the app in fly.toml".to_string(),
        };
        if self.stage {
            format!("Fly.io secret in {app}, staged")
        } else {
            format!("Fly.io secret in {app}")
        }
    }

    async fn push(&self, name: &str, value: &str) -> Result<()> {
        let line = import_line(name, value).map_err(|why| {
            FnoxError::Config(format!(
                "cannot push {name} to Fly.io through fly secrets import: {why}"
            ))
        })?;
        CLI.run(&self.args(), &line).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_and_description() {
        let t: Fly = toml_edit::de::from_str("app = \"api\"\nstage = true").unwrap();
        assert_eq!(t.args(), ["secrets", "import", "--app", "api", "--stage"]);
        assert_eq!(t.describe(), "Fly.io secret in app api, staged");
    }

    #[test]
    fn wraps_values_in_triple_quotes() {
        assert_eq!(import_line("K", "v").unwrap(), "K=\"\"\"v\"\"\"\n");
        assert_eq!(import_line("K", "").unwrap(), "K=\"\"\"\"\"\"\n");
        assert_eq!(
            import_line("K", "a=b \"c\"").unwrap(),
            "K=\"\"\"a=b \"c\"\"\"\"\n"
        );
        assert_eq!(import_line("K", "ab#cd").unwrap(), "K=\"\"\"ab#cd\"\"\"\n");
        assert_eq!(
            import_line("K", "-----BEGIN-----\nabc\n-----END-----\n").unwrap(),
            "K=\"\"\"-----BEGIN-----\nabc\n-----END-----\n\"\"\"\n"
        );
    }

    #[test]
    fn refuses_values_flyctl_would_change() {
        assert!(import_line("K", "a\"b#c").is_err());
        assert!(import_line("K", "a\r\nb").is_err());
        assert!(import_line("K", "a\"\"\"\nb").is_err());
        assert!(import_line("K", &"x".repeat(MAX_LINE + 1)).is_err());
        // A trailing `"""` on the last line is fine: flyctl strips only the closing one
        assert!(import_line("K", "a\nb\"\"\"").is_ok());
    }
}
