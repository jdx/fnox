use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::Provider as _;
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, LazyLock};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Prefix of a reference to one variable of a 1Password Environment:
/// `environment://<environment-id>/<VARIABLE>`.
const ENVIRONMENT_PREFIX: &str = "environment://";

/// Precompiled regex to remove leading error prefixes from stderr output of `op`.
/// [ERROR] YYYY/MM/DD HH:MM:SS message
static ERROR_PREFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\[ERROR\] \d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ").unwrap());

pub struct OnePasswordProvider {
    vault: Option<String>,
    account: Option<String>,
    token: Option<String>,
    /// Variables of each 1Password Environment read so far, keyed by environment ID.
    /// An environment is only readable as a whole bundle, so it is read once and
    /// every variable that references it is served from here.
    environments: Mutex<HashMap<String, Arc<HashMap<String, String>>>>,
}

impl OnePasswordProvider {
    pub fn new(
        vault: Option<String>,
        account: Option<String>,
        token: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            vault,
            account,
            token,
            environments: Mutex::new(HashMap::new()),
        })
    }

    /// Get the service account token, preferring the configured token over environment variable.
    fn get_token(&self) -> Option<String> {
        self.token
            .as_ref()
            .cloned()
            .or_else(op_service_account_token)
    }

    /// Convert a value to an op:// reference
    fn value_to_reference(&self, value: &str) -> Result<String> {
        // Check if value is already a full op:// reference
        if value.starts_with("op://") {
            return Ok(value.to_string());
        }

        if self.vault.is_none() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "1Password".to_string(),
                details: format!("Unknown secret vault for: '{}'", value),
                hint: "Specify a vault in the provider config or use a full 'op://' reference"
                    .to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            });
        }

        // Parse value as "item/field" or just "item"
        // Default field is "password" if not specified
        let parts: Vec<&str> = value.split('/').collect();
        match parts.len() {
            1 => Ok(format!(
                "op://{}/{}/password",
                self.vault.as_ref().unwrap(),
                parts[0]
            )),
            2 => Ok(format!(
                "op://{}/{}/{}",
                self.vault.as_ref().unwrap(),
                parts[0],
                parts[1]
            )),
            _ => Err(FnoxError::ProviderInvalidResponse {
                provider: "1Password".to_string(),
                details: format!("Invalid secret reference format: '{}'", value),
                hint: "Expected 'item', 'item/field', or 'op://vault/item/field'".to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            }),
        }
    }

    /// Read all variables of a 1Password Environment, at most once per provider instance.
    async fn read_environment(&self, id: &str) -> Result<Arc<HashMap<String, String>>> {
        // Held across the read so concurrent lookups of one environment share a single `op` call.
        let mut cache = self.environments.lock().await;
        if let Some(vars) = cache.get(id) {
            return Ok(vars.clone());
        }

        tracing::debug!("Reading 1Password Environment '{}'", id);
        let output = self
            .execute_op_command(&["environment", "read", id])
            .await
            .map_err(|e| match e {
                FnoxError::ProviderCliFailed { details, url, .. }
                    if details.contains("unknown command") =>
                {
                    FnoxError::ProviderCliFailed {
                        provider: "1Password".to_string(),
                        details,
                        hint: "1Password Environments need a 1Password CLI build that includes \
                               'op environment': 2.33.0-beta.02 or later on the beta channel"
                            .to_string(),
                        url,
                    }
                }
                e => e,
            })?;

        let vars = parse_dotenv(&output);
        if vars.is_empty() && !output.is_empty() {
            return Err(FnoxError::ProviderInvalidResponse {
                provider: "1Password".to_string(),
                details: format!(
                    "Could not read variables from the output of 'op environment read {}'",
                    id
                ),
                hint: "Expected dotenv-style KEY=value lines".to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            });
        }
        let vars = Arc::new(vars);
        cache.insert(id.to_string(), vars.clone());
        Ok(vars)
    }

    /// Split `<environment-id>/<VARIABLE>` (the part after `environment://`).
    fn parse_environment_ref(spec: &str) -> Result<(&str, &str)> {
        match spec.split_once('/') {
            Some((id, name)) if !id.is_empty() && !name.is_empty() => Ok((id, name)),
            _ => Err(FnoxError::ProviderInvalidResponse {
                provider: "1Password".to_string(),
                details: format!(
                    "Invalid environment reference: '{}{}'",
                    ENVIRONMENT_PREFIX, spec
                ),
                hint: "Expected 'environment://<environment-id>/<VARIABLE>'".to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            }),
        }
    }

    fn lookup_environment_variable(
        vars: &HashMap<String, String>,
        id: &str,
        name: &str,
    ) -> Result<String> {
        vars.get(name)
            .cloned()
            .ok_or_else(|| FnoxError::ProviderSecretNotFound {
                provider: "1Password".to_string(),
                secret: format!("{}{}/{}", ENVIRONMENT_PREFIX, id, name),
                hint: format!("Environment '{}' has no variable named '{}'", id, name),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            })
    }

    /// Resolve `<environment-id>/<VARIABLE>` (the part after `environment://`).
    async fn get_environment_variable(&self, spec: &str) -> Result<String> {
        let (id, name) = Self::parse_environment_ref(spec)?;
        let vars = self.read_environment(id).await?;
        Self::lookup_environment_variable(&vars, id, name)
    }

    /// Resolve several `(key, <environment-id>/<VARIABLE>)` pairs. Each Environment is
    /// read once; if that read fails, every variable of it gets the same error without
    /// running `op` again. Failures are not cached, so a later batch retries.
    async fn get_environment_variables_batch(
        &self,
        refs: Vec<(String, String)>,
    ) -> HashMap<String, Result<String>> {
        let mut results = HashMap::new();
        let mut by_environment: Vec<(String, Vec<(String, String)>)> = Vec::new();

        for (key, value) in refs {
            let spec = &value[ENVIRONMENT_PREFIX.len()..];
            match Self::parse_environment_ref(spec) {
                Ok((id, name)) => {
                    match by_environment.iter_mut().find(|(env_id, _)| env_id == id) {
                        Some((_, vars)) => vars.push((key, name.to_string())),
                        None => {
                            by_environment.push((id.to_string(), vec![(key, name.to_string())]))
                        }
                    }
                }
                Err(e) => {
                    results.insert(key, Err(e));
                }
            }
        }

        for (id, wanted) in by_environment {
            match self.read_environment(&id).await {
                Ok(vars) => {
                    for (key, name) in wanted {
                        results.insert(key, Self::lookup_environment_variable(&vars, &id, &name));
                    }
                }
                Err(e) => {
                    for (key, _) in wanted {
                        let err = e.clone_provider_error().unwrap_or_else(|| {
                            FnoxError::ProviderCliFailed {
                                provider: "1Password".to_string(),
                                details: e.to_string(),
                                hint: "Check your 1Password configuration and authentication"
                                    .to_string(),
                                url: "https://fnox.jdx.dev/providers/1password".to_string(),
                            }
                        });
                        results.insert(key, Err(err));
                    }
                }
            }
        }

        results
    }

    /// Execute op CLI command with proper authentication
    async fn execute_op_command(&self, args: &[&str]) -> Result<String> {
        tracing::debug!("Executing op command with args: {:?}", args);

        let mut cmd = Command::new("op");
        if let Some(token) = self.get_token() {
            tracing::debug!(
                "Setting OP_SERVICE_ACCOUNT_TOKEN (token length: {})",
                token.len()
            );
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
        }
        cmd.args(args);
        if args.first() == Some(&"environment") {
            // The output is parsed as dotenv lines; don't let a user's OP_FORMAT=json change it.
            cmd.env_remove("OP_FORMAT");
        }

        // Add account flag if specified
        if let Some(account) = &self.account {
            cmd.arg("--account").arg(account);
        }

        let output = cmd.output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "1Password".to_string(),
                    cli: "op".to_string(),
                    install_hint: "brew install 1password-cli".to_string(),
                    url: "https://fnox.jdx.dev/providers/1password".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "1Password".to_string(),
                    details: e.to_string(),
                    hint: "Check that the 1Password CLI is installed and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/1password".to_string(),
                }
            }
        })?;

        if !output.status.success() {
            let cow = String::from_utf8_lossy(&output.stderr);
            let replaced = ERROR_PREFIX_RE.replace_all(&cow, "");
            let stderr = replaced.trim();

            // Check for 1Password CLI auth errors (tested with op CLI v2.x)
            // Common patterns: "not signed in", "authenticate", "authorization invalid"
            if stderr.contains("not signed in")
                || stderr.contains("signed in to an account")
                || stderr.contains("authenticate")
                || stderr.contains("authorization")
                || stderr.contains("session expired")
                || stderr.contains("invalid session")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "1Password".to_string(),
                    details: stderr.to_string(),
                    hint: "Run 'op signin' or set OP_SERVICE_ACCOUNT_TOKEN".to_string(),
                    url: "https://fnox.jdx.dev/providers/1password".to_string(),
                });
            }

            return Err(FnoxError::ProviderCliFailed {
                provider: "1Password".to_string(),
                details: stderr.to_string(),
                hint: "Check your 1Password configuration and authentication".to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "1Password".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            })?;

        Ok(stdout.trim().to_string())
    }

    /// Execute op inject command with stdin/stdout
    async fn execute_op_inject(&self, input: &str) -> Result<String> {
        tracing::debug!("Executing op inject");

        let mut cmd = Command::new("op");
        if let Some(token) = self.get_token() {
            tracing::debug!(
                "Setting OP_SERVICE_ACCOUNT_TOKEN (token length: {})",
                token.len()
            );
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
        }

        // Add account flag if specified
        if let Some(account) = &self.account {
            cmd.arg("--account").arg(account);
        }

        cmd.arg("inject")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FnoxError::ProviderCliNotFound {
                    provider: "1Password".to_string(),
                    cli: "op".to_string(),
                    install_hint: "brew install 1password-cli".to_string(),
                    url: "https://fnox.jdx.dev/providers/1password".to_string(),
                }
            } else {
                FnoxError::ProviderCliFailed {
                    provider: "1Password".to_string(),
                    details: e.to_string(),
                    hint: "Check that the 1Password CLI is installed and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/1password".to_string(),
                }
            }
        })?;

        // Write input to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|e| FnoxError::ProviderCliFailed {
                    provider: "1Password".to_string(),
                    details: format!("Failed to write to stdin: {}", e),
                    hint: "This is an internal error".to_string(),
                    url: "https://fnox.jdx.dev/providers/1password".to_string(),
                })?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| FnoxError::ProviderCliFailed {
                provider: "1Password".to_string(),
                details: format!("Failed to wait for command: {}", e),
                hint: "This is an internal error".to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            })?;

        if !output.status.success() {
            let cow = String::from_utf8_lossy(&output.stderr);
            let replaced = ERROR_PREFIX_RE.replace_all(&cow, "");
            let stderr = replaced.trim();

            // Check for 1Password CLI auth errors (tested with op CLI v2.x)
            // Use same patterns as get_secret for consistency
            if stderr.contains("not signed in")
                || stderr.contains("signed in to an account")
                || stderr.contains("authenticate")
                || stderr.contains("authorization")
                || stderr.contains("session expired")
                || stderr.contains("invalid session")
            {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: "1Password".to_string(),
                    details: stderr.to_string(),
                    hint: "Run 'op signin' or set OP_SERVICE_ACCOUNT_TOKEN".to_string(),
                    url: "https://fnox.jdx.dev/providers/1password".to_string(),
                });
            }

            return Err(FnoxError::ProviderCliFailed {
                provider: "1Password".to_string(),
                details: stderr.to_string(),
                hint: "Check your 1Password configuration and authentication".to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            });
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: "1Password".to_string(),
                details: format!("Invalid UTF-8 in command output: {}", e),
                hint: "The secret value contains invalid UTF-8 characters".to_string(),
                url: "https://fnox.jdx.dev/providers/1password".to_string(),
            })?;

        Ok(stdout)
    }
}

#[async_trait]
impl crate::providers::Provider for OnePasswordProvider {
    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from 1Password", value);

        if let Some(spec) = value.strip_prefix(ENVIRONMENT_PREFIX) {
            return self.get_environment_variable(spec).await;
        }

        let reference = self.value_to_reference(value)?;
        tracing::debug!("Reading 1Password secret: {}", reference);

        // Use 'op read' to fetch the secret
        self.execute_op_command(&["read", &reference]).await
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        // Environment variables come from one `op environment read` per environment;
        // everything else is resolved together through `op inject`.
        let (env_refs, op_refs): (Vec<_>, Vec<_>) = secrets
            .iter()
            .cloned()
            .partition(|(_, value)| value.starts_with(ENVIRONMENT_PREFIX));

        let mut results = self.get_op_secrets_batch(&op_refs).await;
        results.extend(self.get_environment_variables_batch(env_refs).await);
        results
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to 1Password");

        // Try to get the current user as a basic connectivity test
        let output = self.execute_op_command(&["whoami"]).await?;

        tracing::debug!("1Password whoami output: {}", output);

        Ok(())
    }
}

impl OnePasswordProvider {
    /// Resolve vault item references in one `op inject` call.
    async fn get_op_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        tracing::debug!(
            "Getting {} secrets from 1Password using batch mode",
            secrets.len()
        );

        if secrets.is_empty() {
            return HashMap::new();
        }

        // If only one secret, fall back to single get_secret
        if secrets.len() == 1 {
            let (key, value) = &secrets[0];
            let result = self.get_secret(value).await;
            let mut map = HashMap::new();
            map.insert(key.clone(), result);
            return map;
        }

        // Build input for op inject
        // Format: KEY1=op://vault/item/field\nKEY2=op://vault/item2/field2\n...
        let mut input = String::new();
        let mut key_order = Vec::new();
        let mut results = HashMap::new();

        for (key, value) in secrets {
            match self.value_to_reference(value) {
                Ok(reference) => {
                    input.push_str(&format!("{}={}\n", key, reference));
                    key_order.push(key.clone());
                }
                Err(e) => {
                    // If we can't build a reference, add error to results
                    tracing::warn!("Failed to build reference for '{}': {}", key, e);
                    results.insert(key.clone(), Err(e));
                }
            }
        }

        // If all secrets failed to build references, return early
        if key_order.is_empty() {
            return results;
        }

        tracing::debug!("Injecting secrets with input:\n{}", input);

        // Execute op inject with stdin
        match self.execute_op_inject(&input).await {
            Ok(output) => {
                // Parse output handling multi-line secrets
                // Format: KEY1=value1\nKEY2=value2_line1\nvalue2_line2\nKEY3=value3
                // We need to identify where each key starts and collect all lines until the next key
                let mut current_key: Option<String> = None;
                let mut current_value = String::new();

                for line in output.lines() {
                    // Check if this line starts a new key (contains '=' and the prefix matches a key we're looking for)
                    if let Some(eq_pos) = line.find('=') {
                        let potential_key = &line[..eq_pos];

                        // Check if this is one of our expected keys
                        if key_order.iter().any(|k| k == potential_key) {
                            // Save the previous key-value pair if we have one
                            if let Some(key) = current_key.take() {
                                results.insert(key, Ok(current_value.clone()));
                            }

                            // Start collecting the new key
                            current_key = Some(potential_key.to_string());
                            current_value = line[eq_pos + 1..].to_string();
                            continue;
                        }
                    }

                    // This line is a continuation of the current value
                    if current_key.is_some() {
                        if !current_value.is_empty() {
                            current_value.push('\n');
                        }
                        current_value.push_str(line);
                    }
                }

                // Don't forget the last key-value pair
                if let Some(key) = current_key {
                    results.insert(key, Ok(current_value));
                }

                // Check if any secrets are missing from output
                for key in key_order {
                    if !results.contains_key(&key) {
                        results.insert(
                            key.clone(),
                            Err(FnoxError::ProviderSecretNotFound {
                                provider: "1Password".to_string(),
                                secret: key.clone(),
                                hint: "Check that the secret exists in your 1Password vault"
                                    .to_string(),
                                url: "https://fnox.jdx.dev/providers/1password".to_string(),
                            }),
                        );
                    }
                }
            }
            Err(e) => {
                // If op inject failed, fall back to individual get_secret calls
                tracing::warn!("op inject failed, falling back to individual calls: {}", e);
                for (key, value) in secrets {
                    if !results.contains_key(key) {
                        let result = self.get_secret(value).await;
                        results.insert(key.clone(), result);
                    }
                }
            }
        }

        results
    }
}

/// Parse the dotenv-style `KEY=value` lines printed by `op environment read`.
///
/// Accepts an optional `export ` prefix, blank and `#` comment lines, and single- or
/// double-quoted values (which may span lines). Unquoted values are taken verbatim.
fn parse_dotenv(input: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    let mut lines = input.lines();

    while let Some(line) = lines.next() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }

        let raw = raw.trim_start();
        let value = match raw.chars().next() {
            Some(quote @ ('"' | '\'')) => {
                // Quoted: read until the closing quote, continuing onto later lines.
                let mut body = raw[1..].to_string();
                let mut closed = None;
                loop {
                    if let Some(end) = find_closing_quote(&body, quote) {
                        closed = Some(end);
                        break;
                    }
                    match lines.next() {
                        Some(next) => {
                            body.push('\n');
                            body.push_str(next);
                        }
                        None => break,
                    }
                }
                match closed {
                    Some(end) if quote == '"' => unescape_double_quoted(&body[..end]),
                    Some(end) => body[..end].to_string(),
                    // Unterminated quote: keep the text as written.
                    None => raw.to_string(),
                }
            }
            _ => raw.trim_end().to_string(),
        };
        vars.insert(key.to_string(), value);
    }

    vars
}

/// Byte index of the first unescaped `quote` in `s`.
fn find_closing_quote(s: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' && quote == '"' {
            escaped = true;
        } else if c == quote {
            return Some(i);
        }
    }
    None
}

fn unescape_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other @ ('"' | '\\')) => out.push(other),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

pub fn env_dependencies() -> &'static [&'static str] {
    &["OP_SERVICE_ACCOUNT_TOKEN", "FNOX_OP_SERVICE_ACCOUNT_TOKEN"]
}

fn op_service_account_token() -> Option<String> {
    env::var("FNOX_OP_SERVICE_ACCOUNT_TOKEN")
        .or_else(|_| env::var("OP_SERVICE_ACCOUNT_TOKEN"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_exported_lines() {
        let vars = parse_dotenv("# comment\n\nA=1\nexport B=two words\nC=\nbroken line\n");
        assert_eq!(vars["A"], "1");
        assert_eq!(vars["B"], "two words");
        assert_eq!(vars["C"], "");
        assert_eq!(vars.len(), 3);
    }

    #[test]
    fn keeps_equals_and_hash_in_unquoted_values() {
        let vars = parse_dotenv("URL=postgres://u:p@h/db?x=1#frag\n");
        assert_eq!(vars["URL"], "postgres://u:p@h/db?x=1#frag");
    }

    #[test]
    fn parses_quoted_values() {
        let vars =
            parse_dotenv("A=\"say \\\"hi\\\"\\n\"\nB='raw \\n $x'\nC=\"line1\nline2\"\nD=after\n");
        assert_eq!(vars["A"], "say \"hi\"\n");
        assert_eq!(vars["B"], "raw \\n $x");
        assert_eq!(vars["C"], "line1\nline2");
        assert_eq!(vars["D"], "after");
    }

    #[test]
    fn rejects_malformed_environment_references() {
        let provider = OnePasswordProvider::new(None, None, None).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for spec in ["", "abc", "abc/", "/KEY"] {
            let err = rt.block_on(provider.get_environment_variable(spec));
            assert!(
                matches!(err, Err(FnoxError::ProviderInvalidResponse { .. })),
                "{spec:?}"
            );
        }
    }
}
