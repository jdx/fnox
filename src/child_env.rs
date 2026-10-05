//! Plans the environment a child process gets: which secrets and lease
//! credentials to set, which variables to remove, and which `as_file` secrets
//! to write out.
//!
//! `fnox exec` applies a plan to the command it spawns, and `fnox env --json`
//! prints a plan for tools that start processes themselves. Both go through
//! [`plan`], so they cannot drift apart.

use crate::commands::Cli;
use crate::config::{Config, EnvMode, SecretConfig};
use crate::daemon::Purpose;
use crate::error::{FnoxError, Result};
use crate::lease::{self, LeaseLedger};
use crate::lease_backends::LeaseBackendConfig;
use crate::suggest::find_similar;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Which consumer the environment is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvScope {
    /// A command started by `fnox exec`: `env = true` and `env = "exec"` secrets, plus leases.
    Exec,
    /// An interactive shell: `env = true` secrets only, no leases.
    Shell,
}

/// Whether a secret with this `env` mode is injected for `scope`.
pub fn scope_allows(scope: EnvScope, mode: EnvMode) -> bool {
    match scope {
        EnvScope::Exec => mode.in_exec(),
        EnvScope::Shell => mode.in_shell(),
    }
}

/// The daemon cache purpose that matches `scope`.
pub fn scope_purpose(scope: EnvScope) -> Purpose {
    match scope {
        EnvScope::Exec => Purpose::Exec,
        EnvScope::Shell => Purpose::HookEnv,
    }
}

/// Variables a child must not inherit from the ambient environment: the age
/// identity that decrypts other values in the configuration, and the Enpass
/// master password, which unlocks the whole vault. Explicit secrets and lease
/// credentials with these names are still applied after the scrub.
pub fn ambient_scrub_keys() -> impl Iterator<Item = &'static str> {
    ["FNOX_AGE_KEY", "FNOX_AGE_KEY_FILE"].into_iter().chain(
        fnox_core::providers::enpass::env_dependencies()
            .iter()
            .copied(),
    )
}

/// Which keys a plan is built for.
pub enum Roots<'a> {
    /// Every secret is resolved, including `env = false` ones (what `fnox exec` does today).
    AllProfile,
    /// Every secret whose mode is in scope, plus what they depend on.
    Scope,
    /// Exactly these keys, validated by [`select`].
    Keys(&'a [String]),
}

/// The outcome of [`select`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// Secrets whose values are emitted, in config order.
    pub roots: Vec<String>,
    /// Requested keys, deduplicated, when the caller named them.
    pub requested: Option<Vec<String>>,
    /// Leases that run, in config order.
    pub leases: Vec<String>,
    /// Resolve every profile secret instead of the dependency closure of the roots.
    pub resolve_all: bool,
}

/// Why a set of requested keys was rejected.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KeyRejection {
    pub unknown: Vec<String>,
    pub suggestions: IndexMap<String, Vec<String>>,
    pub not_injectable: Vec<NotInjectable>,
}

/// A requested key that is a secret, but not one this scope injects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotInjectable {
    pub key: String,
    pub env: EnvMode,
}

impl KeyRejection {
    pub fn to_error(&self) -> FnoxError {
        let mut help = String::new();
        for (key, similar) in &self.suggestions {
            if !similar.is_empty() {
                help.push_str(&format!(
                    "Did you mean {} instead of {key}?\n",
                    similar.join(" or ")
                ));
            }
        }
        if !self.not_injectable.is_empty() {
            help.push_str(
                "env = false secrets are never injected; read them with `fnox get`. \
                 env = \"exec\" secrets are only injected for `--for exec`.",
            );
        }
        FnoxError::EnvKeysRejected {
            unknown: self.unknown.clone(),
            not_injectable: self.not_injectable.iter().map(|n| n.key.clone()).collect(),
            help: help.trim_end().to_string(),
        }
    }
}

fn secret_mode(secrets: &IndexMap<String, SecretConfig>, key: &str) -> Option<EnvMode> {
    secrets.get(key).map(|secret| secret.env_mode())
}

/// Chooses the roots and leases for a plan. Pure: no I/O.
pub fn select(
    secrets: &IndexMap<String, SecretConfig>,
    leases: &IndexMap<String, LeaseBackendConfig>,
    scope: EnvScope,
    roots: Roots<'_>,
) -> std::result::Result<Selection, KeyRejection> {
    let in_scope_roots = || -> Vec<String> {
        secrets
            .iter()
            .filter(|(_, secret)| scope_allows(scope, secret.env_mode()))
            .map(|(key, _)| key.clone())
            .collect()
    };
    let all_leases = || -> Vec<String> {
        match scope {
            EnvScope::Exec => leases.keys().cloned().collect(),
            EnvScope::Shell => Vec::new(),
        }
    };

    let keys = match roots {
        Roots::AllProfile => {
            return Ok(Selection {
                roots: in_scope_roots(),
                requested: None,
                leases: all_leases(),
                resolve_all: true,
            });
        }
        Roots::Scope => {
            return Ok(Selection {
                roots: in_scope_roots(),
                requested: None,
                leases: all_leases(),
                resolve_all: false,
            });
        }
        Roots::Keys(keys) => keys,
    };

    let mut requested: Vec<String> = Vec::new();
    for key in keys {
        if !requested.contains(key) {
            requested.push(key.clone());
        }
    }

    let mut rejection = KeyRejection::default();
    let mut selected_roots: HashSet<&str> = HashSet::new();
    let mut selected_leases: HashSet<&str> = HashSet::new();
    for key in &requested {
        let mode = secret_mode(secrets, key);
        let is_root = mode.is_some_and(|mode| scope_allows(scope, mode));
        let producing: Vec<&str> = if scope == EnvScope::Exec {
            leases
                .iter()
                .filter(|(_, lease)| lease.produces_env_var(key))
                .map(|(name, _)| name.as_str())
                .collect()
        } else {
            Vec::new()
        };

        if is_root {
            selected_roots.insert(key);
        }
        // A lease wins over a same-name secret, as in `fnox exec`.
        selected_leases.extend(producing.iter().copied());
        if is_root || !producing.is_empty() {
            continue;
        }

        match mode {
            Some(env) => rejection.not_injectable.push(NotInjectable {
                key: key.clone(),
                env,
            }),
            None => {
                let candidates = secrets.keys().map(String::as_str).chain(
                    leases
                        .values()
                        .flat_map(|lease| lease.produced_env_vars().into_iter()),
                );
                let similar = if key.is_empty() {
                    Vec::new()
                } else {
                    find_similar(key, candidates)
                };
                if !similar.is_empty() {
                    rejection
                        .suggestions
                        .insert(key.clone(), similar.into_iter().map(String::from).collect());
                }
                rejection.unknown.push(key.clone());
            }
        }
    }

    if !rejection.unknown.is_empty() || !rejection.not_injectable.is_empty() {
        return Err(rejection);
    }

    Ok(Selection {
        roots: secrets
            .keys()
            .filter(|key| selected_roots.contains(key.as_str()))
            .cloned()
            .collect(),
        requested: Some(requested),
        leases: leases
            .keys()
            .filter(|name| selected_leases.contains(name.as_str()))
            .cloned()
            .collect(),
        resolve_all: false,
    })
}

/// The secrets to hand to the resolver for `sel`.
pub fn resolve_set(
    config: &Config,
    profile: &[String],
    secrets: &IndexMap<String, SecretConfig>,
    leases: &IndexMap<String, LeaseBackendConfig>,
    sel: &Selection,
) -> Result<IndexMap<String, SecretConfig>> {
    if sel.resolve_all {
        return Ok(secrets.clone());
    }
    // A selected lease that does not declare its inputs (a `command` lease) may
    // read any secret, as it can under `fnox exec`. Resolution covers the whole
    // profile; assembly still emits only the roots.
    if sel
        .leases
        .iter()
        .filter_map(|name| leases.get(name))
        .any(|lease| !lease.has_known_inputs())
    {
        return Ok(secrets.clone());
    }

    let mut roots = sel.roots.clone();
    if !sel.leases.is_empty() {
        for name in &sel.leases {
            if let Some(lease) = leases.get(name) {
                roots.extend(lease.consumed_env_vars().iter().map(|key| key.to_string()));
            }
        }
        // The default provider may encrypt cached lease credentials, as `fnox get` allows for.
        if let Ok(Some(default_provider)) = config.get_default_provider(profile)
            && let Some(provider) = config.get_providers(profile)?.get(&default_provider)
        {
            roots.extend(
                provider
                    .env_dependencies()
                    .iter()
                    .map(|key| key.to_string()),
            );
        }
    }
    crate::secret_resolver::dependency_closure(config, profile, secrets, &roots)
}

/// The environment changes for a child process.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChildEnv {
    /// Variables to set.
    pub set: IndexMap<String, String>,
    /// `as_file` secrets: raw contents, for the caller to write to a file and point `KEY` at.
    pub files: IndexMap<String, String>,
    /// Variables to remove from the inherited environment.
    pub remove: Vec<String>,
    /// Requested keys that resolved to nothing.
    pub missing: Vec<String>,
    /// Leases that ran.
    pub leases: Vec<String>,
}

/// Assembles the child environment from resolved values. Pure: no I/O.
///
/// A lease credential beats a same-name secret, an out-of-scope secret is
/// removed, and nothing that is set or written to a file is also removed.
pub fn assemble(
    scope: EnvScope,
    secrets: &IndexMap<String, SecretConfig>,
    leases: &IndexMap<String, LeaseBackendConfig>,
    sel: &Selection,
    resolved: &IndexMap<String, Option<String>>,
    lease_creds: &IndexMap<String, String>,
    leases_used: Vec<String>,
) -> ChildEnv {
    let roots: HashSet<&str> = sel.roots.iter().map(String::as_str).collect();
    let wanted_credential = |key: &str| match &sel.requested {
        Some(requested) => requested.iter().any(|k| k == key),
        None => true,
    };

    let leases_used_names = leases_used.clone();
    let mut out = ChildEnv {
        leases: leases_used,
        ..ChildEnv::default()
    };

    for (key, secret) in secrets {
        if let Some(cred) = lease_creds.get(key) {
            if wanted_credential(key) {
                out.set.insert(key.clone(), cred.clone());
            }
            continue;
        }
        if !roots.contains(key.as_str()) {
            continue;
        }
        match resolved.get(key).and_then(|value| value.as_ref()) {
            Some(value) if secret.as_file => {
                out.files.insert(key.clone(), value.clone());
            }
            Some(value) => {
                out.set.insert(key.clone(), value.clone());
            }
            None => out.missing.push(key.clone()),
        }
    }

    for (key, cred) in lease_creds {
        if !secrets.contains_key(key) && wanted_credential(key) {
            out.set.insert(key.clone(), cred.clone());
        }
    }

    // A requested key that nothing provided: a lease-only key whose lease was
    // skipped, or an out-of-scope secret that no lease replaced.
    if let Some(requested) = &sel.requested {
        for key in requested {
            if !out.set.contains_key(key)
                && !out.files.contains_key(key)
                && !out.missing.contains(key)
            {
                out.missing.push(key.clone());
            }
        }
    }

    // Without `--keys`, the statically known keys of a selected lease that did
    // not run are in scope but resolved to nothing.
    if sel.requested.is_none() {
        for name in sel.leases.iter().filter(|n| !leases_used_names.contains(n)) {
            let Some(lease) = leases.get(name) else {
                continue;
            };
            for key in lease.produced_env_vars() {
                if !out.set.contains_key(key)
                    && !out.files.contains_key(key)
                    && !out.missing.iter().any(|m| m == key)
                {
                    out.missing.push(key.to_string());
                }
            }
        }
    }

    let mut remove: Vec<String> = Vec::new();
    let mut push_remove = |key: &str| {
        if !remove.iter().any(|existing| existing == key) {
            remove.push(key.to_string());
        }
    };
    for key in ambient_scrub_keys() {
        push_remove(key);
    }
    for (key, secret) in secrets {
        if !scope_allows(scope, secret.env_mode()) {
            push_remove(key);
        }
    }
    remove.retain(|key| !out.set.contains_key(key) && !out.files.contains_key(key));
    out.remove = remove;
    out
}

/// Plans the environment for the CLI: select, resolve, run leases, assemble.
///
/// Lease prerequisites and failures follow `fnox exec`: a lease whose
/// prerequisites are missing and that has no cached credential is skipped with
/// a warning, and any other lease error fails the plan. The temporary process
/// environment is gone when this returns. The files created for `as_file`
/// secrets while leases ran are returned, and must outlive the child.
pub async fn plan(
    cli: &Cli,
    config: &Config,
    profile: &[String],
    scope: EnvScope,
    roots: Roots<'_>,
    lease_label: &str,
) -> Result<(ChildEnv, Vec<tempfile::NamedTempFile>)> {
    let secrets = config.get_secrets(profile)?;
    let leases = config.get_leases(profile)?;
    let sel = select(&secrets, &leases, scope, roots).map_err(|rejection| rejection.to_error())?;
    let set = resolve_set(config, profile, &secrets, &leases, &sel)?;

    let resolved = if set.is_empty() && !sel.resolve_all {
        IndexMap::new()
    } else {
        crate::daemon::resolve_batch(cli, config, profile, &set, scope_purpose(scope), true).await?
    };

    let mut lease_creds: IndexMap<String, String> = IndexMap::new();
    let mut leases_used: Vec<String> = Vec::new();

    // Temporarily set resolved secrets as process env vars so lease backend
    // SDKs (AWS, GCP, Azure) can find master credentials during lease creation.
    // The guard removes them on every exit path, including errors.
    let mut _temp_env_guard = lease::TempEnvGuard::default();
    let mut _temp_files = Vec::new();
    if !sel.leases.is_empty() {
        _temp_files.extend(lease::set_secrets_as_env(
            &resolved,
            &secrets,
            &mut _temp_env_guard,
        )?);
        let project_dir = lease::project_dir_from_config(config, &cli.config);
        for (name, lease_config) in leases.iter().filter(|(name, _)| sel.leases.contains(name)) {
            let prereq_missing = lease_config.check_prerequisites();
            if let Some(ref missing) = prereq_missing {
                let has_cache = {
                    let _lock = LeaseLedger::lock(&project_dir)?;
                    let ledger = LeaseLedger::load(&project_dir)?;
                    let config_hash = lease_config.config_hash();
                    ledger
                        .find_reusable(name, &config_hash)
                        .is_some_and(|r| r.cached_credentials.is_some())
                };
                if !has_cache {
                    tracing::warn!(
                        "Skipping lease '{}': {}\nRun 'fnox lease create -i {}' to set up credentials interactively.",
                        name,
                        missing,
                        name
                    );
                    continue;
                }
            }
            // Intentionally hard-fail: if prerequisites pass but lease creation
            // fails, abort rather than run without the expected credentials.
            let creds = lease::resolve_lease(
                name,
                lease_config,
                config,
                profile,
                &project_dir,
                prereq_missing.as_deref(),
                lease_label,
                false,
            )
            .await?;
            leases_used.push(name.clone());
            for (key, value) in creds {
                lease_creds.insert(key, value);
            }
        }
    }
    drop(_temp_env_guard);

    // The lease-time files stay alive for the caller: a lease credential may
    // be a path to one of them, and `fnox exec` keeps them until the child exits.
    Ok((
        assemble(
            scope,
            &secrets,
            &leases,
            &sel,
            &resolved,
            &lease_creds,
            leases_used,
        ),
        _temp_files,
    ))
}

/// Schema version of the documents below. Any breaking change increments it.
pub const ENV_SCHEMA: u32 = 1;

/// Success document of `fnox env --json`.
///
/// Consumers must ignore unknown fields: new optional fields may appear within a schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvDocument {
    pub schema: u32,
    pub fnox_version: String,
    pub scope: EnvScope,
    pub profile: Vec<String>,
    pub set: IndexMap<String, String>,
    pub files: IndexMap<String, String>,
    pub remove: Vec<String>,
    pub missing: Vec<String>,
    pub leases: Vec<String>,
}

impl EnvDocument {
    pub fn new(scope: EnvScope, profile: Vec<String>, env: ChildEnv) -> Self {
        Self {
            schema: ENV_SCHEMA,
            fnox_version: env!("CARGO_PKG_VERSION").to_string(),
            scope,
            profile,
            set: env.set,
            files: env.files,
            remove: env.remove,
            missing: env.missing,
            leases: env.leases,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Secret,
    Lease,
}

/// Where a key may be injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Injectable {
    pub exec: bool,
    pub shell: bool,
}

/// One key in a [`DescribeDocument`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    pub key: String,
    pub kind: KeyKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_file: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub injectable: Injectable,
}

/// Success document of `fnox env --json --describe`: metadata only, no values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescribeDocument {
    pub schema: u32,
    pub fnox_version: String,
    pub profile: Vec<String>,
    pub keys: Vec<KeyInfo>,
    pub dynamic_leases: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Config,
    InvalidKeys,
    Resolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub kind: ErrorKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown: Vec<String>,
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub suggestions: IndexMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_injectable: Vec<NotInjectable>,
}

/// Failure document of `fnox env --json`, written to stdout with exit status 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDocument {
    pub schema: u32,
    pub error: ErrorBody,
}

impl ErrorDocument {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Self {
            schema: ENV_SCHEMA,
            error: ErrorBody {
                kind,
                message,
                unknown: Vec::new(),
                suggestions: IndexMap::new(),
                not_injectable: Vec::new(),
            },
        }
    }

    pub fn invalid_keys(rejection: KeyRejection, message: String) -> Self {
        let mut doc = Self::new(ErrorKind::InvalidKeys, message);
        doc.error.unknown = rejection.unknown;
        doc.error.suggestions = rejection.suggestions;
        doc.error.not_injectable = rejection.not_injectable;
        doc
    }
}

/// Describes the keys a plan could provide, without resolving anything.
///
/// With `requested` (already validated by [`select`]) only those keys are listed.
pub fn describe(
    secrets: &IndexMap<String, SecretConfig>,
    leases: &IndexMap<String, LeaseBackendConfig>,
    requested: Option<&[String]>,
) -> Vec<KeyInfo> {
    // The last lease that produces a key wins, as in `fnox exec`.
    let mut lease_for: IndexMap<&str, &str> = IndexMap::new();
    for (name, lease) in leases {
        for key in lease.produced_env_vars() {
            lease_for.insert(key, name);
        }
    }

    let info = |key: &str| -> KeyInfo {
        let secret = secrets.get(key);
        let lease = lease_for.get(key).copied();
        let env = secret.map(|secret| secret.env_mode());
        KeyInfo {
            key: key.to_string(),
            kind: if lease.is_some() {
                KeyKind::Lease
            } else {
                KeyKind::Secret
            },
            lease: lease.map(String::from),
            env,
            as_file: secret.map(|secret| secret.as_file),
            description: secret.and_then(|secret| secret.description.clone()),
            injectable: Injectable {
                exec: lease.is_some() || env.is_some_and(EnvMode::in_exec),
                shell: env.is_some_and(EnvMode::in_shell),
            },
        }
    };

    match requested {
        Some(requested) => requested.iter().map(|key| info(key)).collect(),
        None => secrets
            .keys()
            .map(String::as_str)
            .chain(
                lease_for
                    .keys()
                    .copied()
                    .filter(|key| !secrets.contains_key(*key)),
            )
            .map(info)
            .collect(),
    }
}

/// Names of `command` lease backends, whose keys are only known after they run.
pub fn dynamic_leases(leases: &IndexMap<String, LeaseBackendConfig>) -> Vec<String> {
    leases
        .iter()
        .filter(|(_, lease)| matches!(lease, LeaseBackendConfig::Command { .. }))
        .map(|(name, _)| name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        toml: &str,
    ) -> (
        IndexMap<String, SecretConfig>,
        IndexMap<String, LeaseBackendConfig>,
    ) {
        let config: Config = toml_edit::de::from_str(toml).unwrap();
        let profile = vec!["default".to_string()];
        (
            config.get_secrets(&profile).unwrap(),
            config.get_leases(&profile).unwrap(),
        )
    }

    const BASE: &str = r#"
root = true
[secrets]
SHELL_OK = { default = "a" }
EXEC_ONLY = { default = "b", env = "exec" }
HIDDEN = { default = "c", env = false }
FILE_SECRET = { default = "f", as_file = true }
[leases.gh]
type = "github-app"
app_id = "1"
installation_id = "2"
env_var = "GH_TOKEN"
[leases.cmd]
type = "command"
create_command = "true"
"#;

    fn keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    fn resolved(entries: &[(&str, Option<&str>)]) -> IndexMap<String, Option<String>> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(String::from)))
            .collect()
    }

    fn creds(entries: &[(&str, &str)]) -> IndexMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ---- select ----

    #[test]
    fn select_reports_unknown_keys_with_suggestions() {
        let (secrets, leases) = fixture(BASE);
        let requested = keys(&["SHEL_OK", "ZZZZZZZZ", ""]);
        let rejection =
            select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).unwrap_err();
        assert_eq!(rejection.unknown, ["SHEL_OK", "ZZZZZZZZ", ""]);
        assert_eq!(rejection.suggestions["SHEL_OK"], ["SHELL_OK"]);
        assert!(!rejection.suggestions.contains_key("ZZZZZZZZ"));
        assert!(!rejection.suggestions.contains_key(""));
        assert!(rejection.not_injectable.is_empty());
    }

    #[test]
    fn select_suggests_statically_known_lease_keys() {
        let (secrets, leases) = fixture(BASE);
        let requested = keys(&["GH_TOKE"]);
        let rejection =
            select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).unwrap_err();
        assert_eq!(rejection.suggestions["GH_TOKE"], ["GH_TOKEN"]);
    }

    #[test]
    fn select_reports_env_false_as_not_injectable() {
        let (secrets, leases) = fixture(BASE);
        let requested = keys(&["HIDDEN"]);
        let rejection =
            select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).unwrap_err();
        assert!(rejection.unknown.is_empty());
        assert_eq!(
            rejection.not_injectable,
            [NotInjectable {
                key: "HIDDEN".to_string(),
                env: EnvMode::Never
            }]
        );
    }

    #[test]
    fn select_reports_exec_mode_under_shell_scope() {
        let (secrets, leases) = fixture(BASE);
        let requested = keys(&["EXEC_ONLY"]);
        let rejection =
            select(&secrets, &leases, EnvScope::Shell, Roots::Keys(&requested)).unwrap_err();
        assert_eq!(rejection.not_injectable[0].env, EnvMode::Exec);
        assert!(
            select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).is_ok(),
            "exec scope accepts env = \"exec\""
        );
    }

    #[test]
    fn select_deduplicates_keeping_the_first_occurrence() {
        let (secrets, leases) = fixture(BASE);
        let requested = keys(&["EXEC_ONLY", "SHELL_OK", "EXEC_ONLY"]);
        let sel = select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).unwrap();
        assert_eq!(sel.requested.unwrap(), ["EXEC_ONLY", "SHELL_OK"]);
        // Roots keep config order.
        assert_eq!(sel.roots, ["SHELL_OK", "EXEC_ONLY"]);
    }

    #[test]
    fn select_accepts_lease_keys_and_selects_the_lease() {
        let (secrets, leases) = fixture(BASE);
        let requested = keys(&["GH_TOKEN"]);
        let sel = select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).unwrap();
        assert!(sel.roots.is_empty());
        assert_eq!(sel.leases, ["gh"]);
    }

    #[test]
    fn select_lease_wins_over_an_env_false_secret_of_the_same_name() {
        let (secrets, leases) = fixture(&format!(
            "{BASE}\n[secrets.GH_TOKEN]\ndefault = \"master\"\nenv = false\n"
        ));
        let requested = keys(&["GH_TOKEN"]);
        let sel = select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).unwrap();
        assert_eq!(sel.leases, ["gh"]);
        assert!(sel.roots.is_empty());
    }

    #[test]
    fn select_reports_command_lease_keys_as_unknown() {
        let (secrets, leases) = fixture(BASE);
        let requested = keys(&["MY_TOKEN"]);
        let rejection =
            select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).unwrap_err();
        assert_eq!(rejection.unknown, ["MY_TOKEN"]);
    }

    #[test]
    fn select_shell_never_selects_leases() {
        let (secrets, leases) = fixture(BASE);
        let sel = select(&secrets, &leases, EnvScope::Shell, Roots::Scope).unwrap();
        assert!(sel.leases.is_empty());
        assert_eq!(sel.roots, ["SHELL_OK", "FILE_SECRET"]);

        let requested = keys(&["GH_TOKEN"]);
        let rejection =
            select(&secrets, &leases, EnvScope::Shell, Roots::Keys(&requested)).unwrap_err();
        assert_eq!(rejection.unknown, ["GH_TOKEN"]);
    }

    #[test]
    fn select_exec_scope_selects_every_lease() {
        let (secrets, leases) = fixture(BASE);
        let sel = select(&secrets, &leases, EnvScope::Exec, Roots::Scope).unwrap();
        assert_eq!(sel.leases, ["gh", "cmd"]);
        assert_eq!(sel.roots, ["SHELL_OK", "EXEC_ONLY", "FILE_SECRET"]);
        assert!(!sel.resolve_all);
        assert!(
            select(&secrets, &leases, EnvScope::Exec, Roots::AllProfile)
                .unwrap()
                .resolve_all
        );
    }

    // ---- assemble ----

    fn assemble_for(
        scope: EnvScope,
        toml: &str,
        roots: Roots<'_>,
        resolved: &IndexMap<String, Option<String>>,
        lease_creds: &IndexMap<String, String>,
        leases_used: &[&str],
    ) -> ChildEnv {
        let (secrets, leases) = fixture(toml);
        let sel = select(&secrets, &leases, scope, roots).unwrap();
        assemble(
            scope,
            &secrets,
            &leases,
            &sel,
            resolved,
            lease_creds,
            leases_used.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn assemble_sets_files_and_removes_the_rest() {
        let env = assemble_for(
            EnvScope::Exec,
            BASE,
            Roots::Scope,
            &resolved(&[
                ("SHELL_OK", Some("a")),
                ("EXEC_ONLY", Some("b")),
                ("HIDDEN", Some("c")),
                ("FILE_SECRET", Some("f")),
            ]),
            &creds(&[]),
            &["gh", "cmd"],
        );
        assert_eq!(env.set, creds(&[("SHELL_OK", "a"), ("EXEC_ONLY", "b")]));
        assert_eq!(env.files, creds(&[("FILE_SECRET", "f")]));
        assert_eq!(
            env.remove,
            [
                "FNOX_AGE_KEY",
                "FNOX_AGE_KEY_FILE",
                "ENPASS_PASSWORD",
                "FNOX_ENPASS_PASSWORD",
                "HIDDEN"
            ]
        );
        assert!(env.missing.is_empty());
    }

    #[test]
    fn assemble_never_removes_what_it_sets() {
        let toml = r#"
root = true
[secrets]
FNOX_AGE_KEY = { default = "explicit" }
"#;
        let env = assemble_for(
            EnvScope::Exec,
            toml,
            Roots::AllProfile,
            &resolved(&[("FNOX_AGE_KEY", Some("explicit"))]),
            &creds(&[]),
            &[],
        );
        assert_eq!(env.set, creds(&[("FNOX_AGE_KEY", "explicit")]));
        assert!(!env.remove.contains(&"FNOX_AGE_KEY".to_string()));
        assert!(env.remove.contains(&"FNOX_AGE_KEY_FILE".to_string()));
    }

    #[test]
    fn assemble_lease_value_beats_an_env_false_secret() {
        let toml = format!("{BASE}\n[secrets.GH_TOKEN]\ndefault = \"master\"\nenv = false\n");
        let env = assemble_for(
            EnvScope::Exec,
            &toml,
            Roots::AllProfile,
            &resolved(&[("GH_TOKEN", Some("master"))]),
            &creds(&[("GH_TOKEN", "short-lived")]),
            &["gh"],
        );
        assert_eq!(env.set["GH_TOKEN"], "short-lived");
        assert!(!env.remove.contains(&"GH_TOKEN".to_string()));
        assert_eq!(env.leases, ["gh"]);
    }

    #[test]
    fn assemble_lease_value_replaces_a_secret_in_place_and_new_ones_follow() {
        let toml = r#"
root = true
[secrets]
FIRST = { default = "1" }
GH_TOKEN = { default = "master" }
LAST = { default = "3" }
"#;
        let (secrets, _) = fixture(toml);
        let leases: IndexMap<String, LeaseBackendConfig> = toml_edit::de::from_str::<Config>(
            "root = true\n[leases.gh]\ntype = \"github-app\"\napp_id = \"1\"\ninstallation_id = \"2\"\n[leases.az]\ntype = \"azure-token\"\nscope = \"s\"\n",
        )
        .unwrap()
        .get_leases(&["default".to_string()])
        .unwrap();
        let sel = select(&secrets, &leases, EnvScope::Exec, Roots::AllProfile).unwrap();
        let env = assemble(
            EnvScope::Exec,
            &secrets,
            &leases,
            &sel,
            &resolved(&[
                ("FIRST", Some("1")),
                ("GH_TOKEN", Some("master")),
                ("LAST", Some("3")),
            ]),
            &creds(&[("EXTRA", "x"), ("GH_TOKEN", "lease")]),
            vec!["gh".to_string()],
        );
        assert_eq!(
            env.set
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>(),
            [
                ("FIRST", "1"),
                ("GH_TOKEN", "lease"),
                ("LAST", "3"),
                ("EXTRA", "x")
            ]
        );
    }

    #[test]
    fn assemble_env_false_none_goes_to_remove_in_all_profile() {
        let env = assemble_for(
            EnvScope::Exec,
            BASE,
            Roots::AllProfile,
            &resolved(&[
                ("SHELL_OK", Some("a")),
                ("EXEC_ONLY", Some("b")),
                ("HIDDEN", None),
                ("FILE_SECRET", Some("f")),
            ]),
            &creds(&[]),
            &["gh", "cmd"],
        );
        assert!(env.remove.contains(&"HIDDEN".to_string()));
        assert!(env.missing.is_empty());
    }

    #[test]
    fn assemble_in_scope_none_goes_to_missing() {
        let env = assemble_for(
            EnvScope::Exec,
            BASE,
            Roots::Scope,
            &resolved(&[
                ("SHELL_OK", None),
                ("EXEC_ONLY", Some("b")),
                ("FILE_SECRET", None),
            ]),
            &creds(&[]),
            &["gh", "cmd"],
        );
        assert_eq!(env.missing, ["SHELL_OK", "FILE_SECRET"]);
        assert_eq!(env.set, creds(&[("EXEC_ONLY", "b")]));
    }

    #[test]
    fn assemble_keys_mode_drops_unrequested_lease_credentials() {
        let requested = keys(&["SHELL_OK", "GH_TOKEN"]);
        let env = assemble_for(
            EnvScope::Exec,
            BASE,
            Roots::Keys(&requested),
            &resolved(&[("SHELL_OK", Some("a"))]),
            &creds(&[("GH_TOKEN", "t"), ("OTHER_CRED", "x")]),
            &["gh"],
        );
        assert_eq!(env.set, creds(&[("SHELL_OK", "a"), ("GH_TOKEN", "t")]));
        assert!(env.missing.is_empty());
    }

    #[test]
    fn assemble_keys_mode_removes_env_false_secret_named_like_an_unrequested_credential() {
        let toml = format!("{BASE}\n[secrets.OTHER_CRED]\ndefault = \"master\"\nenv = false\n");
        let requested = keys(&["GH_TOKEN"]);
        let env = assemble_for(
            EnvScope::Exec,
            &toml,
            Roots::Keys(&requested),
            &resolved(&[]),
            &creds(&[("GH_TOKEN", "t"), ("OTHER_CRED", "lease")]),
            &["gh"],
        );
        assert!(!env.set.contains_key("OTHER_CRED"));
        assert!(env.remove.contains(&"OTHER_CRED".to_string()));
    }

    #[test]
    fn assemble_all_profile_still_sets_a_lease_credential_over_an_env_false_secret() {
        let toml = format!("{BASE}\n[secrets.OTHER_CRED]\ndefault = \"master\"\nenv = false\n");
        let env = assemble_for(
            EnvScope::Exec,
            &toml,
            Roots::AllProfile,
            &resolved(&[("OTHER_CRED", Some("master"))]),
            &creds(&[("OTHER_CRED", "lease")]),
            &["gh"],
        );
        assert_eq!(env.set["OTHER_CRED"], "lease");
        assert!(!env.remove.contains(&"OTHER_CRED".to_string()));
    }

    #[test]
    fn resolve_set_covers_the_whole_profile_for_a_command_lease() {
        let config: Config = toml_edit::de::from_str(BASE).unwrap();
        let profile = vec!["default".to_string()];
        let secrets = config.get_secrets(&profile).unwrap();
        let leases = config.get_leases(&profile).unwrap();

        let sel = select(&secrets, &leases, EnvScope::Exec, Roots::Scope).unwrap();
        let set = resolve_set(&config, &profile, &secrets, &leases, &sel).unwrap();
        assert!(set.contains_key("HIDDEN"));
        // Only roots are emitted, so the hidden value is still never set.
        assert!(!sel.roots.contains(&"HIDDEN".to_string()));

        let requested = keys(&["SHELL_OK"]);
        let sel = select(&secrets, &leases, EnvScope::Exec, Roots::Keys(&requested)).unwrap();
        let set = resolve_set(&config, &profile, &secrets, &leases, &sel).unwrap();
        assert_eq!(set.keys().collect::<Vec<_>>(), ["SHELL_OK"]);
    }

    #[test]
    fn assemble_scope_mode_reports_skipped_lease_keys_as_missing() {
        let toml = r#"
root = true
[secrets]
FOO = { default = "foo" }
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::1:role/r"
[leases.cmd]
type = "command"
create_command = "true"
"#;
        let env = assemble_for(
            EnvScope::Exec,
            toml,
            Roots::Scope,
            &resolved(&[("FOO", Some("foo"))]),
            &creds(&[]),
            &[],
        );
        assert_eq!(
            env.missing,
            [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN"
            ]
        );

        // A lease that ran reports nothing.
        let ran = assemble_for(
            EnvScope::Exec,
            toml,
            Roots::Scope,
            &resolved(&[("FOO", Some("foo"))]),
            &creds(&[
                ("AWS_ACCESS_KEY_ID", "a"),
                ("AWS_SECRET_ACCESS_KEY", "b"),
                ("AWS_SESSION_TOKEN", "c"),
            ]),
            &["aws", "cmd"],
        );
        assert!(ran.missing.is_empty());
    }

    #[test]
    fn assemble_skipped_lease_key_goes_to_missing() {
        let requested = keys(&["GH_TOKEN"]);
        let env = assemble_for(
            EnvScope::Exec,
            BASE,
            Roots::Keys(&requested),
            &resolved(&[]),
            &creds(&[]),
            &[],
        );
        assert_eq!(env.missing, ["GH_TOKEN"]);
        assert!(env.leases.is_empty());
    }

    #[test]
    fn assemble_shell_scope_removes_exec_only_secrets() {
        let env = assemble_for(
            EnvScope::Shell,
            BASE,
            Roots::Scope,
            &resolved(&[("SHELL_OK", Some("a")), ("FILE_SECRET", Some("f"))]),
            &creds(&[]),
            &[],
        );
        assert!(env.remove.contains(&"EXEC_ONLY".to_string()));
        assert!(env.remove.contains(&"HIDDEN".to_string()));
        assert!(!env.set.contains_key("EXEC_ONLY"));
    }

    // ---- describe ----

    #[test]
    fn describe_lists_every_key_with_where_it_may_be_injected() {
        let (secrets, leases) = fixture(BASE);
        let infos = describe(&secrets, &leases, None);
        let summary: Vec<_> = infos
            .iter()
            .map(|i| {
                (
                    i.key.as_str(),
                    i.kind,
                    i.injectable.exec,
                    i.injectable.shell,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("SHELL_OK", KeyKind::Secret, true, true),
                ("EXEC_ONLY", KeyKind::Secret, true, false),
                ("HIDDEN", KeyKind::Secret, false, false),
                ("FILE_SECRET", KeyKind::Secret, true, true),
                ("GH_TOKEN", KeyKind::Lease, true, false),
            ]
        );
        assert_eq!(dynamic_leases(&leases), ["cmd"]);
    }

    // ---- golden documents: these pin schema 1 ----

    #[test]
    fn golden_env_document() {
        let doc = EnvDocument {
            schema: 1,
            fnox_version: "1.38.0".to_string(),
            scope: EnvScope::Exec,
            profile: keys(&["default"]),
            set: creds(&[("DATABASE_URL", "postgres://x")]),
            files: creds(&[("GCP_SA_JSON", "{}")]),
            remove: keys(&["FNOX_AGE_KEY", "SIGNING_KEY"]),
            missing: keys(&["OPTIONAL_TOKEN"]),
            leases: keys(&["aws"]),
        };
        assert_eq!(
            serde_json::to_string(&doc).unwrap(),
            r#"{"schema":1,"fnox_version":"1.38.0","scope":"exec","profile":["default"],"set":{"DATABASE_URL":"postgres://x"},"files":{"GCP_SA_JSON":"{}"},"remove":["FNOX_AGE_KEY","SIGNING_KEY"],"missing":["OPTIONAL_TOKEN"],"leases":["aws"]}"#
        );
    }

    #[test]
    fn golden_describe_document() {
        let doc = DescribeDocument {
            schema: 1,
            fnox_version: "1.38.0".to_string(),
            profile: keys(&["default"]),
            keys: vec![
                KeyInfo {
                    key: "DATABASE_URL".to_string(),
                    kind: KeyKind::Secret,
                    lease: None,
                    env: Some(EnvMode::Shell),
                    as_file: Some(false),
                    description: Some("Main DB".to_string()),
                    injectable: Injectable {
                        exec: true,
                        shell: true,
                    },
                },
                KeyInfo {
                    key: "STRIPE_KEY".to_string(),
                    kind: KeyKind::Secret,
                    lease: None,
                    env: Some(EnvMode::Exec),
                    as_file: Some(false),
                    description: None,
                    injectable: Injectable {
                        exec: true,
                        shell: false,
                    },
                },
                KeyInfo {
                    key: "SIGNING_KEY".to_string(),
                    kind: KeyKind::Secret,
                    lease: None,
                    env: Some(EnvMode::Never),
                    as_file: Some(false),
                    description: None,
                    injectable: Injectable {
                        exec: false,
                        shell: false,
                    },
                },
                KeyInfo {
                    key: "AWS_ACCESS_KEY_ID".to_string(),
                    kind: KeyKind::Lease,
                    lease: Some("aws".to_string()),
                    env: None,
                    as_file: None,
                    description: None,
                    injectable: Injectable {
                        exec: true,
                        shell: false,
                    },
                },
            ],
            dynamic_leases: keys(&["build_token"]),
        };
        assert_eq!(
            serde_json::to_string(&doc).unwrap(),
            r#"{"schema":1,"fnox_version":"1.38.0","profile":["default"],"keys":[{"key":"DATABASE_URL","kind":"secret","env":true,"as_file":false,"description":"Main DB","injectable":{"exec":true,"shell":true}},{"key":"STRIPE_KEY","kind":"secret","env":"exec","as_file":false,"injectable":{"exec":true,"shell":false}},{"key":"SIGNING_KEY","kind":"secret","env":false,"as_file":false,"injectable":{"exec":false,"shell":false}},{"key":"AWS_ACCESS_KEY_ID","kind":"lease","lease":"aws","injectable":{"exec":true,"shell":false}}],"dynamic_leases":["build_token"]}"#
        );
    }

    #[test]
    fn golden_error_document() {
        let rejection = KeyRejection {
            unknown: keys(&["DEPLOY_KYE"]),
            suggestions: IndexMap::from([("DEPLOY_KYE".to_string(), keys(&["DEPLOY_KEY"]))]),
            not_injectable: vec![NotInjectable {
                key: "SIGNING_KEY".to_string(),
                env: EnvMode::Never,
            }],
        };
        let doc = ErrorDocument::invalid_keys(rejection, "bad keys".to_string());
        assert_eq!(
            serde_json::to_string(&doc).unwrap(),
            r#"{"schema":1,"error":{"kind":"invalid_keys","message":"bad keys","unknown":["DEPLOY_KYE"],"suggestions":{"DEPLOY_KYE":["DEPLOY_KEY"]},"not_injectable":[{"key":"SIGNING_KEY","env":false}]}}"#
        );
        let plain = ErrorDocument::new(ErrorKind::Config, "boom".to_string());
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            r#"{"schema":1,"error":{"kind":"config","message":"boom"}}"#
        );
    }
}
