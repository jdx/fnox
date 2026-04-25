//! Library convenience API for downstream consumers.
//!
//! The lower-level [`Config`] / [`secret_resolver::resolve_secret`] /
//! [`commands`] surface is sufficient but CLI-shaped — every consumer
//! ends up replicating what [`commands::get::GetCommand::run`] does
//! (load config, walk profile secrets, resolve, handle missing). The
//! [`Fnox`] type wraps that boilerplate so consumers that just want
//! "give me this secret" can write three lines instead of thirty.
//!
//! Designed in response to
//! <https://github.com/jdx/fnox/discussions/441> ("Library API:
//! top-level Fnox::discover() / get / set / list for downstream
//! consumers"). First cut covers `get` and `list`. `set` is left to a
//! follow-up because the orchestration in
//! [`commands::set::SetCommand::run`] (provider/encryption/remote-
//! storage branching, base64, dry-run) is substantial enough to
//! warrant its own design pass.
//!
//! ## Usage
//!
//! ```no_run
//! # async fn run() -> fnox::Result<()> {
//! use fnox::Fnox;
//!
//! // Walks up from CWD to find fnox.toml — same as the binary.
//! let fnox = Fnox::discover()?;
//! let value = fnox.get("MY_KEY").await?;
//! let names = fnox.list().await?;
//! # Ok(()) }
//! ```

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::{FnoxError, Result};

/// Default profile when callers don't specify one. Matches the
/// binary's default (no `--profile` flag → `"default"`).
pub const DEFAULT_PROFILE: &str = "default";

/// Filename the binary discovers via upward search. Re-exported so
/// callers can probe with the same name fnox itself uses.
pub const CONFIG_FILENAME: &str = "fnox.toml";

/// Convenience client over [`Config`] — load once, query many.
///
/// Cheap to clone (just a [`Config`] + a [`String`] profile). Hold
/// across `.await` freely.
#[derive(Debug, Clone)]
pub struct Fnox {
    config: Config,
    profile: String,
}

impl Fnox {
    /// Walk up from the current directory looking for `fnox.toml`.
    /// Loads it via [`Config::load_smart`] — the same path the binary
    /// takes when invoked without an explicit `--config` flag.
    ///
    /// Returns [`FnoxError`] if no `fnox.toml` is found above CWD or
    /// if loading/parsing fails.
    pub fn discover() -> Result<Self> {
        let start = std::env::current_dir()
            .map_err(|e| FnoxError::Config(format!("Failed to read current directory: {e}")))?;
        Self::discover_from(&start)
    }

    /// Like [`Fnox::discover`] but starts the upward search from a
    /// specific path. Useful for tests, daemons running in a different
    /// CWD than the project root, etc.
    pub fn discover_from(start: impl AsRef<Path>) -> Result<Self> {
        let mut current: PathBuf = start.as_ref().to_path_buf();
        loop {
            let candidate = current.join(CONFIG_FILENAME);
            if candidate.exists() {
                let config = Config::load_smart(&candidate)?;
                return Ok(Self {
                    config,
                    profile: DEFAULT_PROFILE.to_string(),
                });
            }
            if !current.pop() {
                return Err(FnoxError::Config(format!(
                    "No {CONFIG_FILENAME} found above {}",
                    start.as_ref().display()
                )));
            }
        }
    }

    /// Open an explicit config path. Skips the upward search.
    pub fn open(config_path: impl AsRef<Path>) -> Result<Self> {
        let config = Config::load_smart(config_path)?;
        Ok(Self {
            config,
            profile: DEFAULT_PROFILE.to_string(),
        })
    }

    /// Use a specific profile instead of `default`. Builder-style.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Active profile name.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Borrow the underlying [`Config`] for callers that need
    /// finer-grained access (e.g., enumerating providers, walking
    /// secret metadata) without re-parsing.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Resolve a secret by name. Returns the resolved value, or
    /// `None` if the key is declared with `if_missing = "ignore"` and
    /// has no value.
    ///
    /// Returns an error if the key isn't declared in the active
    /// profile, or if the configured backend fails (network error,
    /// auth failure, decryption failure, etc.).
    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        let secrets = self.config.get_secrets(&self.profile)?;
        let secret_config = secrets.get(key).ok_or_else(|| {
            FnoxError::Config(format!(
                "Secret '{key}' not declared in profile '{}'",
                self.profile
            ))
        })?;
        crate::secret_resolver::resolve_secret(&self.config, &self.profile, key, secret_config)
            .await
    }

    /// Declared secret names for the active profile, in declaration
    /// order. Note this is the *declared* set from `fnox.toml`, not
    /// necessarily the set of secrets that currently have a resolvable
    /// value (some may be `if_missing = "ignore"`).
    pub async fn list(&self) -> Result<Vec<String>> {
        let secrets = self.config.get_secrets(&self.profile)?;
        Ok(secrets.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Given a tempdir containing a minimal fnox.toml,
    /// when discover_from() is called pointing at the dir,
    /// then it loads successfully with the default profile.
    #[test]
    fn discover_from_finds_adjacent_fnox_toml() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(CONFIG_FILENAME), "").unwrap();

        let fnox = Fnox::discover_from(dir.path()).expect("discover should succeed");
        assert_eq!(fnox.profile(), DEFAULT_PROFILE);
    }

    /// Given a tempdir containing fnox.toml at the parent,
    /// when discover_from() starts in a child subdirectory,
    /// then it walks up and finds the parent's fnox.toml.
    #[test]
    fn discover_from_walks_up_to_parent_fnox_toml() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(CONFIG_FILENAME), "").unwrap();
        let child = dir.path().join("a/b/c");
        fs::create_dir_all(&child).unwrap();

        let fnox = Fnox::discover_from(&child).expect("upward search should succeed");
        assert_eq!(fnox.profile(), DEFAULT_PROFILE);
    }

    /// Given a tempdir with NO fnox.toml,
    /// when discover_from() is called,
    /// then it returns a clear error naming the start path.
    #[test]
    fn discover_from_errors_with_clear_message_when_no_config() {
        let dir = TempDir::new().unwrap();
        let err = Fnox::discover_from(dir.path()).expect_err("should fail");
        let msg = err.to_string();
        assert!(
            msg.contains(CONFIG_FILENAME),
            "error must name the config filename so users know what's missing; got: {msg}"
        );
    }

    /// Given a fnox.toml declaring two secrets in default profile,
    /// when list() is called,
    /// then both names come back, in declaration order.
    #[tokio::test]
    async fn list_returns_declared_secrets_in_declaration_order() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(CONFIG_FILENAME),
            r#"
[secrets]
ZFIRST = { default = "first-default" }
ASECOND = { default = "second-default" }
"#,
        )
        .unwrap();

        let fnox = Fnox::discover_from(dir.path()).unwrap();
        let names = fnox.list().await.unwrap();
        assert_eq!(
            names,
            vec!["ZFIRST".to_string(), "ASECOND".to_string()],
            "list must preserve declaration order, not sort alphabetically"
        );
    }

    /// Given a fnox.toml declaring a secret with a default value,
    /// when get() is called for that key,
    /// then the default value comes back.
    #[tokio::test]
    async fn get_returns_default_value_when_no_provider_or_env() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(CONFIG_FILENAME),
            r#"
[secrets]
LIB_TEST_DEFAULTS_KEY = { default = "the-default-value" }
"#,
        )
        .unwrap();

        // Defensive: clear any matching env so the env-var fallback
        // doesn't shadow the default we're trying to test. Name is
        // unique to this test to avoid cross-test races.
        // Safety: process-global env mutation; the unique name keeps
        // the blast radius to this one test.
        unsafe { std::env::remove_var("LIB_TEST_DEFAULTS_KEY") };

        let fnox = Fnox::discover_from(dir.path()).unwrap();
        let value = fnox
            .get("LIB_TEST_DEFAULTS_KEY")
            .await
            .expect("get should succeed");
        assert_eq!(value, Some("the-default-value".to_string()));
    }

    /// Given a fnox.toml that doesn't declare a key,
    /// when get() is called for it,
    /// then the error names the missing key + profile so the user can
    /// fix their fnox.toml without needing to read source.
    #[tokio::test]
    async fn get_errors_clearly_when_key_not_declared() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(CONFIG_FILENAME), "").unwrap();

        let fnox = Fnox::discover_from(dir.path()).unwrap();
        let err = fnox.get("UNDECLARED").await.expect_err("must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("UNDECLARED") && msg.contains("default"),
            "error must name the key AND the profile; got: {msg}"
        );
    }

    /// Given an explicit profile via with_profile,
    /// when list() is called,
    /// then secrets declared in that profile come back. (Whether
    /// default-profile secrets are inherited is a fnox semantics
    /// question covered elsewhere; this test only asserts that the
    /// profile selector reaches the right section.)
    #[tokio::test]
    async fn with_profile_routes_list_to_named_profile() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(CONFIG_FILENAME),
            r#"
[profiles.staging.secrets]
LIB_TEST_PROFILE_KEY = { default = "y" }
"#,
        )
        .unwrap();

        let fnox = Fnox::discover_from(dir.path())
            .unwrap()
            .with_profile("staging");
        assert_eq!(fnox.profile(), "staging");
        let names = fnox.list().await.unwrap();
        assert!(
            names.contains(&"LIB_TEST_PROFILE_KEY".to_string()),
            "profile-specific secret must appear in list; got: {names:?}"
        );
    }
}
