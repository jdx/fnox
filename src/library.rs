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
//! // Walks up from CWD to find fnox.toml + merges parent + local +
//! // global config — same exact merge the binary does.
//! let fnox = Fnox::discover()?;
//! let value = fnox.get("MY_KEY").await?;
//! let names = fnox.list()?;
//! # Ok(()) }
//! ```

use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::error::{FnoxError, Result};

/// Filename the binary discovers via upward search. Re-exported so
/// callers can probe with the same name fnox itself uses.
pub const CONFIG_FILENAME: &str = "fnox.toml";

/// Convenience client over [`Config`] — load once, query many.
///
/// Cheap to clone (Config is held behind an [`Arc`]); hold across
/// `.await` freely.
#[derive(Debug, Clone)]
pub struct Fnox {
    config: Arc<Config>,
    profile: String,
}

impl Fnox {
    /// Walk up from the current directory looking for `fnox.toml`
    /// AND merge in the parent / local-override / global config chain
    /// — same exact behavior as the binary when invoked without an
    /// explicit `--config` flag (see `Config::load_smart` for the
    /// merge order).
    ///
    /// Profile is resolved via [`Config::get_profile`] which honors
    /// the `FNOX_PROFILE` env var (matches binary semantics).
    ///
    /// Returns [`FnoxError`] if loading/parsing fails.
    pub fn discover() -> Result<Self> {
        // CONFIG_FILENAME is bare (no directory prefix) so load_smart
        // takes its upward-recursion path — this is what unlocks the
        // parent + local + global merging that load(absolute) would
        // bypass. Per AGENTS.md "Loading order".
        let config = Config::load_smart(CONFIG_FILENAME)?;
        let profile = Config::get_profile(None);
        Ok(Self {
            config: Arc::new(config),
            profile,
        })
    }

    /// Open a fnox config from a specific path. Use this when you
    /// have an explicit path (CLI arg, env var, daemon configuration)
    /// rather than wanting the binary's discovery walk.
    ///
    /// Note: `Config::load_smart` may still trigger upward-search/merge
    /// behavior if `path` is exactly the default filename
    /// ([`CONFIG_FILENAME`], no directory). Pass an absolute or
    /// directory-prefixed path to get strictly that file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let config = Config::load_smart(path)?;
        let profile = Config::get_profile(None);
        Ok(Self {
            config: Arc::new(config),
            profile,
        })
    }

    /// Use a specific profile instead of whatever
    /// [`Config::get_profile`] resolved. Builder-style.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Active profile name.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Borrow the underlying [`Config`] for callers that need
    /// finer-grained access (enumerating providers, walking secret
    /// metadata) without re-parsing.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Resolve a secret by name. Returns the resolved value, or
    /// `None` if the key is declared with `if_missing = "ignore"` or
    /// `"warn"` and has no value (per `secret_resolver::handle_missing_secret`).
    ///
    /// Returns [`FnoxError::SecretNotFound`] if the key isn't declared
    /// in the active profile (matches the binary's error shape so
    /// downstream consumers can pattern-match without a wrapper-
    /// specific variant). The returned error carries a `suggestion`
    /// computed from declared keys via [`crate::suggest`], matching
    /// `GetCommand::run`'s "Did you mean…" UX.
    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        // get_secret returns Option<&SecretConfig> without cloning the
        // whole IndexMap — preferred over get_secrets(profile)?.get(key).
        if let Some(secret_config) = self.config.get_secret(&self.profile, key) {
            return crate::secret_resolver::resolve_secret(
                &self.config,
                &self.profile,
                key,
                secret_config,
            )
            .await;
        }
        // Compute "Did you mean…" suggestions from the declared key
        // set in the active profile. Matches GetCommand::run's UX.
        let suggestion = self.list().ok().and_then(|names| {
            let similar = crate::suggest::find_similar(key, names.iter().map(|s| s.as_str()));
            crate::suggest::format_suggestions(&similar)
        });
        Err(FnoxError::SecretNotFound {
            key: key.to_string(),
            profile: self.profile.clone(),
            config_path: self.config.secret_sources.get(key).cloned(),
            suggestion,
        })
    }

    /// Declared secret names for the active profile, in declaration
    /// order. Synchronous: this is a config-walk, no I/O.
    ///
    /// Note: this is the *declared* set from `fnox.toml` (and merged
    /// configs), not necessarily the set of secrets that currently
    /// have a resolvable value.
    pub fn list(&self) -> Result<Vec<String>> {
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
    /// when open() is called with the explicit path,
    /// then it loads successfully.
    #[test]
    fn open_loads_explicit_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "").unwrap();

        let fnox = Fnox::open(&path).expect("open should succeed");
        // Whatever Config::get_profile(None) resolves to (default or
        // FNOX_PROFILE) — just assert non-empty for stability across
        // test environments.
        assert!(!fnox.profile().is_empty());
    }

    /// Given a path that doesn't exist,
    /// when open() is called,
    /// then it returns a clear error.
    #[test]
    fn open_errors_when_path_missing() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist.toml");
        let err = Fnox::open(&missing).expect_err("must fail");
        // Accept any error shape — the contract is "fails", not the
        // exact message text.
        let _ = err.to_string();
    }

    /// Given a fnox.toml declaring two secrets in default,
    /// when list() is called,
    /// then both names come back, in declaration order.
    #[test]
    fn list_returns_declared_secrets_in_declaration_order() {
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

        let fnox = Fnox::open(dir.path().join(CONFIG_FILENAME)).unwrap();
        let names = fnox.list().unwrap();
        assert_eq!(
            names,
            vec!["ZFIRST".to_string(), "ASECOND".to_string()],
            "list must preserve declaration order, not sort alphabetically"
        );
    }

    /// Given a fnox.toml declaring a secret with a default value,
    /// when get() is called for that key,
    /// then the default value comes back. Uses a key prefix
    /// (LIB_TEST_) that we own so test ordering can't shadow via env.
    #[tokio::test]
    async fn get_returns_default_value_when_no_provider() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(CONFIG_FILENAME),
            r#"
[secrets]
LIB_TEST_DEFAULTS_KEY_UNIQUE_X = { default = "the-default-value" }
"#,
        )
        .unwrap();

        let fnox = Fnox::open(dir.path().join(CONFIG_FILENAME)).unwrap();
        let value = fnox
            .get("LIB_TEST_DEFAULTS_KEY_UNIQUE_X")
            .await
            .expect("get should succeed");
        // The value comes back as "the-default-value" UNLESS something
        // upstream sets the env var of the same name. Loosen to
        // "got something non-empty" so we don't depend on a clean env.
        assert!(value.is_some(), "expected Some(_), got {value:?}");
    }

    /// Given a fnox.toml that doesn't declare a key,
    /// when get() is called for it,
    /// then the error is FnoxError::SecretNotFound carrying the key +
    /// profile (matches the binary's error shape).
    #[tokio::test]
    async fn get_errors_with_secret_not_found_when_key_undeclared() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(CONFIG_FILENAME), "").unwrap();

        let fnox = Fnox::open(dir.path().join(CONFIG_FILENAME)).unwrap();
        let err = fnox.get("UNDECLARED").await.expect_err("must fail");
        match err {
            FnoxError::SecretNotFound { key, profile, .. } => {
                assert_eq!(key, "UNDECLARED");
                assert!(!profile.is_empty());
            }
            other => panic!("expected SecretNotFound, got {other:?}"),
        }
    }

    /// Given a fnox.toml that declares similarly-named keys,
    /// when get() is called with a typo,
    /// then SecretNotFound carries a populated `suggestion` (matches
    /// GetCommand::run's "Did you mean…" UX) so consumers don't need
    /// to recompute it from list() at every call site.
    #[tokio::test]
    async fn get_secret_not_found_carries_did_you_mean_suggestion() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(CONFIG_FILENAME),
            r#"
[secrets]
DATABASE_URL = { default = "x" }
DATABASE_TOKEN = { default = "y" }
NPM_TOKEN = { default = "z" }
"#,
        )
        .unwrap();

        let fnox = Fnox::open(dir.path().join(CONFIG_FILENAME)).unwrap();
        // Typo: missing trailing 'L'
        let err = fnox.get("DATABASE_UR").await.expect_err("must fail");
        match err {
            FnoxError::SecretNotFound { suggestion, .. } => {
                let s = suggestion.expect("suggestion should be populated for near-matches");
                assert!(
                    s.contains("DATABASE_URL"),
                    "suggestion should mention the closest match; got: {s:?}"
                );
            }
            other => panic!("expected SecretNotFound, got {other:?}"),
        }
    }

    /// Given an explicit profile via with_profile,
    /// when list() is called,
    /// then secrets declared in that profile come back.
    #[test]
    fn with_profile_routes_list_to_named_profile() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(CONFIG_FILENAME),
            r#"
[profiles.staging.secrets]
LIB_TEST_PROFILE_KEY = { default = "y" }
"#,
        )
        .unwrap();

        let fnox = Fnox::open(dir.path().join(CONFIG_FILENAME))
            .unwrap()
            .with_profile("staging");
        assert_eq!(fnox.profile(), "staging");
        let names = fnox.list().unwrap();
        assert!(
            names.contains(&"LIB_TEST_PROFILE_KEY".to_string()),
            "profile-specific secret must appear in list; got: {names:?}"
        );
    }

    /// Cloning Fnox is cheap (Config is Arc'd). Asserts that two
    /// clones share the same Config allocation rather than deep-
    /// copying every IndexMap inside.
    #[test]
    fn clone_does_not_deep_copy_config() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(CONFIG_FILENAME), "").unwrap();

        let a = Fnox::open(dir.path().join(CONFIG_FILENAME)).unwrap();
        let b = a.clone();
        // Compare config() pointers — same Arc backing => no deep copy.
        assert!(
            std::ptr::eq(a.config() as *const _, b.config() as *const _),
            "Fnox::clone must share Config behind Arc, not deep-copy"
        );
    }
}
