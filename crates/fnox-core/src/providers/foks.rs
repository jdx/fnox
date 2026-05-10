use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use tokio::process::Command;
use tokio::sync::Mutex;

const PROVIDER_NAME: &str = "FOKS";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/foks";

/// Provider that integrates with FOKS (https://foks.pub) via the `foks` CLI.
///
/// Secrets are stored as values in the FOKS encrypted key-value store, either
/// in the user's personal namespace or under a team. fnox shells out to the
/// `foks` CLI; the FOKS agent (`foks ctl start`) handles authentication and
/// end-to-end encryption.
///
/// For non-interactive environments (CI), set `bot_token` (or pass it via the
/// `FOKS_BOT_TOKEN` / `FNOX_FOKS_BOT_TOKEN` env var) along with `host`. On the
/// first auth failure during a fnox run, the provider transparently calls
/// `foks bot use --host <host>` with the token, then retries the operation.
pub struct FoksProvider {
    prefix: Option<String>,
    team: Option<String>,
    home: Option<String>,
    host: Option<String>,
    bot_token: Option<String>,
    /// One-shot guard: ensures the bot-token auto-login is attempted at most
    /// once per provider instance, no matter how many concurrent secrets are
    /// being fetched. Stores `true` once we've tried (success or failure).
    login_attempted: Mutex<bool>,
}

impl FoksProvider {
    pub fn new(
        prefix: Option<String>,
        team: Option<String>,
        home: Option<String>,
        host: Option<String>,
        bot_token: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            prefix,
            team,
            home,
            host,
            bot_token,
            login_attempted: Mutex::new(false),
        })
    }

    /// Build the full KV path with optional prefix.
    fn build_secret_path(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{prefix}{key}"),
            None => key.to_string(),
        }
    }

    /// Resolve the FOKS home directory: explicit config wins, otherwise fall
    /// back to FNOX_FOKS_HOME / FOKS_HOME, otherwise `None` (foks uses its
    /// default).
    fn resolved_home(&self) -> Option<String> {
        resolve_with_env(self.home.as_deref(), &["FNOX_FOKS_HOME", "FOKS_HOME"])
    }

    /// Resolve the FOKS host: explicit config wins, otherwise FNOX_FOKS_HOST /
    /// FOKS_HOST. Required for bot-token auto-login; for normal interactive
    /// use it can be omitted (the agent already knows the active host).
    fn resolved_host(&self) -> Option<String> {
        resolve_with_env(self.host.as_deref(), &["FNOX_FOKS_HOST", "FOKS_HOST"])
    }

    /// Resolve the bot token: explicit config wins, otherwise
    /// FNOX_FOKS_BOT_TOKEN / FOKS_BOT_TOKEN. Returning `None` here disables
    /// the auto-login retry path entirely.
    fn resolved_bot_token(&self) -> Option<String> {
        resolve_with_env(
            self.bot_token.as_deref(),
            &["FNOX_FOKS_BOT_TOKEN", "FOKS_BOT_TOKEN"],
        )
    }

    /// Args common to every `foks kv ...` invocation: -H/--home (if set) and
    /// -t/--team (if set). Returned as owned strings so the caller can borrow
    /// them as &str.
    fn common_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(home) = self.resolved_home() {
            args.push("--home".to_string());
            args.push(home);
        }
        if let Some(team) = self.team.as_deref()
            && !team.is_empty()
        {
            args.push("--team".to_string());
            args.push(team.to_string());
        }
        args
    }

    fn new_command(&self) -> Command {
        let mut cmd = Command::new("foks");
        for arg in self.common_args() {
            cmd.arg(arg);
        }
        cmd
    }

    /// Single attempt at running `foks kv ...` with no stdin. Returns trimmed
    /// stdout on success; classifies the stderr on failure. Does not retry.
    async fn execute_foks_kv_once(
        &self,
        args: &[&str],
        secret_ref: Option<&str>,
    ) -> Result<String> {
        tracing::debug!("Executing foks kv command with args: {args:?}");

        let mut cmd = self.new_command();
        cmd.arg("kv");
        cmd.args(args);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = cmd.output().await.map_err(map_spawn_error)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_cli_error(stderr.trim(), secret_ref));
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Invalid UTF-8 in command output: {e}"),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }

    /// Run a `foks kv ...` command, transparently retrying once after a
    /// successful bot-token auto-login if the first attempt failed with an
    /// auth error and a bot token is configured.
    async fn execute_foks_kv(&self, args: &[&str], secret_ref: Option<&str>) -> Result<String> {
        match self.execute_foks_kv_once(args, secret_ref).await {
            Ok(v) => Ok(v),
            Err(err) => {
                if self.try_auto_login_for(&err).await? {
                    self.execute_foks_kv_once(args, secret_ref).await
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Single attempt at running `foks kv put <path>` with `value` written to
    /// stdin. Used by `put_secret`; the retry wrapper lives in `put_secret`
    /// itself.
    async fn execute_foks_kv_put_once(&self, path: &str, value: &str) -> Result<()> {
        let mut cmd = self.new_command();
        cmd.arg("kv")
            .arg("put")
            .arg("--force")
            .arg("--mkdir-p")
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(map_spawn_error)?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin
                .write_all(value.as_bytes())
                .await
                .map_err(|e| FnoxError::ProviderCliFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details: format!("Failed to write secret to foks stdin: {e}"),
                    hint: "This is an internal error".to_string(),
                    url: PROVIDER_URL.to_string(),
                })?;
            // Closing stdin signals EOF; foks treats EOF as end-of-value.
            drop(stdin);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Failed to wait for 'foks kv put': {e}"),
                hint: "This is an internal error".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_cli_error(stderr.trim(), Some(path)));
        }
        Ok(())
    }

    /// If `err` is an auth failure and a bot token is configured, run
    /// `foks bot use --host <host>` exactly once for this provider instance.
    /// Returns `Ok(true)` if a login was performed (caller should retry the
    /// failing op), `Ok(false)` if no auto-login was attempted (caller should
    /// surface the original error). A login that itself fails is returned as
    /// `Err`.
    async fn try_auto_login_for(&self, err: &FnoxError) -> Result<bool> {
        if !matches!(err, FnoxError::ProviderAuthFailed { .. }) {
            return Ok(false);
        }
        let Some(token) = self.resolved_bot_token() else {
            return Ok(false);
        };
        let Some(host) = self.resolved_host() else {
            tracing::warn!(
                "FOKS bot_token is configured but no host is set; skipping auto-login. \
                 Set the `host` field or FOKS_HOST env var."
            );
            return Ok(false);
        };

        let mut attempted = self.login_attempted.lock().await;
        if *attempted {
            return Ok(false);
        }
        *attempted = true;

        tracing::info!("FOKS auth failed; attempting bot-token auto-login on host {host}");
        self.run_bot_login(&host, &token).await?;
        Ok(true)
    }

    /// Run `foks bot use --host <host>` with the bot token piped via the
    /// FOKS_BOT_TOKEN env var (so it never appears on the command line / in
    /// `ps` output).
    async fn run_bot_login(&self, host: &str, token: &str) -> Result<()> {
        let mut cmd = self.new_command();
        cmd.arg("bot")
            .arg("use")
            .arg("--host")
            .arg(host)
            .env("FOKS_BOT_TOKEN", token)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let output = cmd.output().await.map_err(map_spawn_error)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details: format!("foks bot use failed: {}", stderr.trim()),
                hint: "Check that the bot token is valid and that the host matches the FOKS server it was issued on".to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }
        tracing::debug!("FOKS bot-token auto-login succeeded");
        Ok(())
    }
}

/// Map a spawn-time IO error from `Command::output` / `Command::spawn` to a
/// `FnoxError`. Shared by all `foks` invocations so missing-CLI vs other-IO
/// errors stay consistent.
fn map_spawn_error(e: std::io::Error) -> FnoxError {
    if e.kind() == std::io::ErrorKind::NotFound {
        FnoxError::ProviderCliNotFound {
            provider: PROVIDER_NAME.to_string(),
            cli: "foks".to_string(),
            install_hint: "brew install foks (or see https://foks.pub)".to_string(),
            url: PROVIDER_URL.to_string(),
        }
    } else {
        FnoxError::ProviderCliFailed {
            provider: PROVIDER_NAME.to_string(),
            details: e.to_string(),
            hint: "Check that the foks CLI is installed and on PATH".to_string(),
            url: PROVIDER_URL.to_string(),
        }
    }
}

/// Resolve a value: prefer the explicit `Option<&str>` (after trimming empty
/// strings), then fall back to the first non-empty value among `env_vars`,
/// then `None`.
fn resolve_with_env(explicit: Option<&str>, env_vars: &[&str]) -> Option<String> {
    if let Some(s) = explicit
        && !s.is_empty()
    {
        return Some(s.to_string());
    }
    for v in env_vars {
        if let Ok(s) = env::var(v)
            && !s.is_empty()
        {
            return Some(s);
        }
    }
    None
}

#[async_trait]
impl crate::providers::Provider for FoksProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let path = self.build_secret_path(value);
        tracing::debug!("Getting secret '{path}' from FOKS");
        // `foks kv get <path>` prints the value to stdout (no output file).
        self.execute_foks_kv(&["get", &path], Some(&path)).await
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let path = self.build_secret_path(key);
        tracing::debug!("Storing secret '{path}' in FOKS");

        match self.execute_foks_kv_put_once(&path, value).await {
            Ok(()) => {}
            Err(err) => {
                if self.try_auto_login_for(&err).await? {
                    self.execute_foks_kv_put_once(&path, value).await?;
                } else {
                    return Err(err);
                }
            }
        }

        tracing::debug!("Successfully stored secret '{path}' in FOKS");
        Ok(key.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to FOKS");
        // `foks kv ls /` exercises the agent + KV path without touching any
        // particular key. Output is discarded.
        self.execute_foks_kv(&["ls", "/"], None).await?;
        tracing::debug!("FOKS connection test successful");
        Ok(())
    }
}

pub fn env_dependencies() -> &'static [&'static str] {
    &[
        "FOKS_HOME",
        "FNOX_FOKS_HOME",
        "FOKS_HOST",
        "FNOX_FOKS_HOST",
        "FOKS_BOT_TOKEN",
        "FNOX_FOKS_BOT_TOKEN",
    ]
}

/// Patterns that indicate the FOKS agent is unreachable or the user is not
/// authenticated. The most common cause is forgetting to run `foks ctl start`
/// or `foks signup` / `foks login`.
const AUTH_ERROR_PATTERNS: &[&str] = &[
    "could not connect to the foks agent",
    "no logged-in user",
    "no current user",
    "not logged in",
    "auth required",
    "permission denied",
];

/// Patterns that indicate the requested KV entry does not exist. FOKS uses
/// "no rows in result set" (a postgres-style message bubbling up from the
/// server) and the more user-facing "not found" / "no such" wording.
const SECRET_NOT_FOUND_PATTERNS: &[&str] = &[
    "no rows in result set",
    "not found",
    "no such file or directory",
    "no such key",
    "does not exist",
];

fn contains_any(haystack: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| haystack.contains(p))
}

/// Classify FOKS CLI stderr output into the appropriate FnoxError variant.
fn classify_cli_error(stderr: &str, secret_ref: Option<&str>) -> FnoxError {
    let stderr_lower = stderr.to_lowercase();

    if contains_any(&stderr_lower, AUTH_ERROR_PATTERNS) {
        return FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details: stderr.to_string(),
            hint: "Start the FOKS agent (`foks ctl start`) and ensure you are signed in (`foks signup` or `foks login`)".to_string(),
            url: PROVIDER_URL.to_string(),
        };
    }

    if let Some(secret_name) = secret_ref
        && contains_any(&stderr_lower, SECRET_NOT_FOUND_PATTERNS)
    {
        return FnoxError::ProviderSecretNotFound {
            provider: PROVIDER_NAME.to_string(),
            secret: secret_name.to_string(),
            hint: "Check that the key exists in the FOKS KV store (try `foks kv ls`)".to_string(),
            url: PROVIDER_URL.to_string(),
        };
    }

    FnoxError::ProviderCliFailed {
        provider: PROVIDER_NAME.to_string(),
        details: stderr.to_string(),
        hint: "Check your FOKS configuration and that the agent is running".to_string(),
        url: PROVIDER_URL.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(prefix: Option<&str>, team: Option<&str>, home: Option<&str>) -> FoksProvider {
        FoksProvider::new(
            prefix.map(String::from),
            team.map(String::from),
            home.map(String::from),
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn build_secret_path_with_prefix() {
        let p = provider(Some("fnox/"), None, None);
        assert_eq!(p.build_secret_path("MY_SECRET"), "fnox/MY_SECRET");
    }

    #[test]
    fn build_secret_path_without_prefix() {
        let p = provider(None, None, None);
        assert_eq!(p.build_secret_path("MY_SECRET"), "MY_SECRET");
    }

    #[test]
    fn common_args_empty_by_default() {
        let p = provider(None, None, None);
        assert!(p.common_args().is_empty());
    }

    #[test]
    fn common_args_team_and_home() {
        let p = provider(None, Some("eng"), Some("/tmp/foks"));
        assert_eq!(
            p.common_args(),
            vec!["--home", "/tmp/foks", "--team", "eng"]
        );
    }

    #[test]
    fn common_args_skips_empty_strings() {
        // Empty strings can come through from the wizard / config and should
        // not produce dangling `--team ""` flags.
        let p = provider(None, Some(""), Some(""));
        assert!(p.common_args().is_empty());
    }

    #[test]
    fn classify_agent_unreachable_is_auth_failed() {
        let err = classify_cli_error(
            "Error: could not connect to the FOKS agent; start it via `foks ctl start`",
            None,
        );
        assert!(
            matches!(err, FnoxError::ProviderAuthFailed { .. }),
            "Expected ProviderAuthFailed, got {err:?}"
        );
    }

    #[test]
    fn classify_no_logged_in_user_is_auth_failed() {
        let err = classify_cli_error("no logged-in user", Some("MY_SECRET"));
        assert!(matches!(err, FnoxError::ProviderAuthFailed { .. }));
    }

    #[test]
    fn classify_missing_key_is_secret_not_found() {
        let err = classify_cli_error("Error: no rows in result set", Some("/fnox/MY_SECRET"));
        match err {
            FnoxError::ProviderSecretNotFound { secret, .. } => {
                assert_eq!(secret, "/fnox/MY_SECRET");
            }
            other => panic!("Expected ProviderSecretNotFound, got {other:?}"),
        }
    }

    #[test]
    fn classify_missing_key_without_ref_is_cli_failed() {
        // Without a secret_ref to attach, "not found" should fall through to
        // the generic CLI-failed bucket rather than a misleading
        // ProviderSecretNotFound with an empty secret name.
        let err = classify_cli_error("not found", None);
        assert!(matches!(err, FnoxError::ProviderCliFailed { .. }));
    }

    #[test]
    fn classify_unknown_error_is_cli_failed() {
        let err = classify_cli_error("kv put failed: disk full", Some("/fnox/MY_SECRET"));
        assert!(matches!(err, FnoxError::ProviderCliFailed { .. }));
    }

    #[test]
    fn env_dependencies_lists_foks_home_and_bot_token() {
        let deps = env_dependencies();
        assert!(deps.contains(&"FOKS_HOME"));
        assert!(deps.contains(&"FNOX_FOKS_HOME"));
        assert!(deps.contains(&"FOKS_HOST"));
        assert!(deps.contains(&"FNOX_FOKS_HOST"));
        assert!(deps.contains(&"FOKS_BOT_TOKEN"));
        assert!(deps.contains(&"FNOX_FOKS_BOT_TOKEN"));
    }

    #[test]
    fn resolve_with_env_prefers_explicit() {
        // Set the env var to a sentinel; explicit value should still win.
        // SAFETY: tests run single-threaded for env mutation; this test name
        // is unique within the suite.
        // We use a unique env-var name per test to avoid cross-test races.
        let env_name = "FNOX_FOKS_RESOLVE_TEST_EXPLICIT";
        // SAFETY: safe in tests; we restore with remove_var on each branch.
        unsafe { std::env::set_var(env_name, "from-env") };
        let r = resolve_with_env(Some("from-config"), &[env_name]);
        unsafe { std::env::remove_var(env_name) };
        assert_eq!(r.as_deref(), Some("from-config"));
    }

    #[test]
    fn resolve_with_env_falls_back_to_first_set_env() {
        let primary = "FNOX_FOKS_RESOLVE_TEST_PRIMARY";
        let secondary = "FNOX_FOKS_RESOLVE_TEST_SECONDARY";
        // SAFETY: see above.
        unsafe {
            std::env::remove_var(primary);
            std::env::set_var(secondary, "fallback");
        }
        let r = resolve_with_env(None, &[primary, secondary]);
        unsafe { std::env::remove_var(secondary) };
        assert_eq!(r.as_deref(), Some("fallback"));
    }

    #[test]
    fn resolve_with_env_treats_empty_string_as_absent() {
        // Empty string from the wizard should NOT shadow a set env var.
        let env_name = "FNOX_FOKS_RESOLVE_TEST_EMPTY";
        // SAFETY: see above.
        unsafe { std::env::set_var(env_name, "from-env") };
        let r = resolve_with_env(Some(""), &[env_name]);
        unsafe { std::env::remove_var(env_name) };
        assert_eq!(r.as_deref(), Some("from-env"));
    }

    #[tokio::test]
    async fn try_auto_login_for_skips_non_auth_errors() {
        let p = provider(None, None, None);
        let err = FnoxError::ProviderCliFailed {
            provider: PROVIDER_NAME.to_string(),
            details: "kv put failed".to_string(),
            hint: String::new(),
            url: PROVIDER_URL.to_string(),
        };
        assert!(!p.try_auto_login_for(&err).await.unwrap());
    }

    #[tokio::test]
    async fn try_auto_login_for_skips_when_no_bot_token() {
        let p = provider(None, None, None);
        let err = FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details: "no logged-in user".to_string(),
            hint: String::new(),
            url: PROVIDER_URL.to_string(),
        };
        // With no bot_token configured (and no env var set), auto-login is a
        // no-op and the original error should bubble up unchanged.
        assert!(!p.try_auto_login_for(&err).await.unwrap());
    }
}
