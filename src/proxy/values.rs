//! The real values of rule secrets. A secret that isn't set when the proxy
//! starts is pending: its placeholder is handed out, requests that need it are
//! refused, and the proxy resolves it again when a request needs it, so a
//! value set during the run starts working without a restart.

use super::*;
use std::time::{Duration, Instant};

use crate::secret_session::SecretSession;

/// How often a pending secret may be resolved again
const PENDING_RETRY: Duration = Duration::from_secs(3);

/// How long a request waits for a pending secret to resolve before it is
/// refused as not set
const PENDING_LOAD_TIMEOUT: Duration = Duration::from_secs(15);

/// What a rule needs to redact its secret from responses
#[derive(Debug, Clone)]
pub(super) struct RuleRedaction {
    pub(super) secret: String,
    pub(super) placeholder: String,
    pub(super) lenient: bool,
    /// A lease's value is created, never set, so it is not pending
    pub(super) lease: bool,
}

#[derive(Debug, Default)]
struct Attempts {
    /// Last time each pending secret was resolved again
    last: HashMap<String, Instant>,
    /// Pending secrets being resolved now
    in_flight: HashSet<String>,
}

#[derive(Debug, Default)]
struct State {
    values: HashMap<String, String>,
    /// Values replaced during the run, still redacted from responses: a
    /// request sent with one may finish after the replacement
    retired: Vec<(String, String)>,
    redactions: Arc<Vec<Redaction>>,
}

#[derive(Debug)]
pub(super) struct SecretValues {
    rules: Vec<RuleRedaction>,
    state: std::sync::RwLock<State>,
    /// Where pending secrets are resolved from; without one they stay pending
    session: std::sync::OnceLock<Arc<SecretSession>>,
    /// Shared with a config reload still running on the blocking pool
    attempts: Arc<std::sync::Mutex<Attempts>>,
}

impl SecretValues {
    /// `values` holds the secrets that resolved at startup; every rule secret
    /// missing from it is pending
    pub(super) fn new(rules: Vec<RuleRedaction>, values: HashMap<String, String>) -> Self {
        let state = State {
            redactions: Arc::new(build_redactions(&rules, &values, &[])),
            values,
            retired: Vec::new(),
        };
        Self {
            rules,
            state: std::sync::RwLock::new(state),
            session: std::sync::OnceLock::new(),
            attempts: Arc::new(std::sync::Mutex::new(Attempts::default())),
        }
    }

    pub(super) fn set_session(&self, session: Arc<SecretSession>) {
        let _ = self.session.set(session);
    }

    pub(super) fn value(&self, secret: &str) -> Option<String> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values
            .get(secret)
            .cloned()
    }

    pub(super) fn redactions(&self) -> Arc<Vec<Redaction>> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .redactions
            .clone()
    }

    /// Rule secrets that have no value yet
    pub(super) fn pending(&self) -> Vec<String> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let mut pending: Vec<String> = Vec::new();
        for rule in self.rules.iter().filter(|rule| !rule.lease) {
            if !state.values.contains_key(&rule.secret) && !pending.contains(&rule.secret) {
                pending.push(rule.secret.clone());
            }
        }
        pending
    }

    /// Use `value` for a still-pending `secret`; returns whether it was. A
    /// refresh never replaces a value: that would drop the old value's
    /// redaction while a response that echoes it may still be in flight.
    pub(super) fn fill(&self, secret: &str, value: String) -> Result<bool> {
        if self.value(secret).is_some() {
            return Ok(false);
        }
        self.set_checked(secret, value, true)
    }

    /// Use `value` for `secret` from now on, replacing any value it has. The
    /// replaced value stays redacted from responses for the rest of the run.
    pub(super) fn replace(&self, secret: &str, value: String) -> Result<()> {
        self.set_checked(secret, value, false).map(|_| ())
    }

    /// Make `secret` pending again, so the next request that needs it
    /// resolves it from the config as it is on disk. The value it had stays
    /// redacted from responses for the rest of the run.
    pub(super) fn forget(&self, secret: &str) {
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            let Some(old) = state.values.remove(secret) else {
                return;
            };
            state.retired.push((secret.to_string(), old));
            state.redactions =
                Arc::new(build_redactions(&self.rules, &state.values, &state.retired));
        }
        // Due at once, not after PENDING_RETRY
        self.attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last
            .remove(secret);
    }

    /// The checks a value gets before the proxy uses it, the same as at
    /// startup
    pub(super) fn validate(&self, secret: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            return Err(proxy_error(format!(
                "secret '{secret}' resolved to an empty value"
            )));
        }
        for rule in &self.rules {
            if rule.secret == secret && rule.placeholder == value {
                return Err(proxy_error(format!(
                    "placeholder for '{secret}' must differ from the real value"
                )));
            }
            if value.contains(rule.placeholder.as_str()) {
                return Err(proxy_error(
                    "a real secret value cannot contain a configured placeholder",
                ));
            }
        }
        Ok(())
    }

    /// Use `value` for `secret` after the checks startup values get, unless
    /// `only_if_pending` and it already has a value
    fn set_checked(&self, secret: &str, value: String, only_if_pending: bool) -> Result<bool> {
        self.validate(secret, &value)?;
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        if only_if_pending && state.values.contains_key(secret) {
            return Ok(false);
        }
        if let Some(old) = state.values.insert(secret.to_string(), value)
            && state.values.get(secret) != Some(&old)
        {
            state.retired.push((secret.to_string(), old));
        }
        state.redactions = Arc::new(build_redactions(&self.rules, &state.values, &state.retired));
        Ok(true)
    }

    /// Resolve the pending ones among `secrets` again, each at most once per
    /// [`PENDING_RETRY`] and never twice at once, from the config as it is on
    /// disk now
    pub(super) async fn refresh(&self, secrets: &[&str]) {
        let Some(session) = self.session.get() else {
            return;
        };
        // Pick the due secrets and record the attempt before any slow work,
        // so a failed config reload also waits PENDING_RETRY and another
        // request doesn't load the same secret meanwhile. The lock is not
        // held while providers run.
        let due: Vec<String> = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            let mut attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let mut due: Vec<String> = Vec::new();
            for secret in secrets {
                if state.values.contains_key(*secret)
                    || due.iter().any(|picked| picked == secret)
                    || attempts.in_flight.contains(*secret)
                    || attempts
                        .last
                        .get(*secret)
                        .is_some_and(|last| now.duration_since(*last) < PENDING_RETRY)
                {
                    continue;
                }
                attempts.last.insert(secret.to_string(), now);
                attempts.in_flight.insert(secret.to_string());
                due.push(secret.to_string());
            }
            due
        };
        if due.is_empty() {
            return;
        }
        // Clears the in-flight marks however this ends, including when the
        // request is dropped mid-load
        let in_flight = Arc::new(InFlight {
            attempts: self.attempts.clone(),
            secrets: due.clone(),
        });
        // Reading the config is blocking file I/O: keep it off the async
        // workers, and within the same deadline as the lookups. A timeout
        // can't stop the blocking task, so it keeps the marks until it ends;
        // otherwise every later request could start another stalled reload.
        let reload = tokio::task::spawn_blocking({
            let session = session.clone();
            let in_flight = in_flight.clone();
            move || {
                let _in_flight = in_flight;
                session.load_config()
            }
        });
        let config = match tokio::time::timeout(PENDING_LOAD_TIMEOUT, reload).await {
            Ok(Ok(Ok(config))) => config,
            Ok(Ok(Err(error))) => {
                tracing::warn!("fnox proxy: could not reload the config: {error}");
                return;
            }
            Ok(Err(error)) => {
                tracing::warn!("fnox proxy: config reload failed: {error}");
                return;
            }
            Err(_) => {
                tracing::warn!(
                    "fnox proxy: reloading the config took longer than {}s",
                    PENDING_LOAD_TIMEOUT.as_secs()
                );
                return;
            }
        };
        for secret in &due {
            let loaded = tokio::time::timeout(PENDING_LOAD_TIMEOUT, session.load(&config, secret));
            let Ok(loaded) = loaded.await else {
                tracing::warn!(
                    "fnox proxy: resolving '{secret}' took longer than {}s; it stays pending",
                    PENDING_LOAD_TIMEOUT.as_secs()
                );
                continue;
            };
            match loaded {
                Ok(true) => {
                    let Some(Some(value)) = session.cached(secret).await else {
                        continue;
                    };
                    match self.fill(secret, value) {
                        Ok(true) => tracing::info!(
                            target: "fnox::proxy",
                            secret = secret.as_str(),
                            "pending secret is now set"
                        ),
                        Ok(false) => {}
                        Err(error) => tracing::warn!("fnox proxy: {error}"),
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!("fnox proxy: could not resolve '{secret}': {error}")
                }
            }
        }
    }
}

/// Removes the in-flight marks of a refresh when it, and the config reload it
/// started, have both ended
struct InFlight {
    attempts: Arc<std::sync::Mutex<Attempts>>,
    secrets: Vec<String>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        for secret in &self.secrets {
            attempts.in_flight.remove(secret);
        }
    }
}

/// One redaction per distinct value, longest first, so a value that contains
/// another is replaced whole
fn build_redactions(
    rules: &[RuleRedaction],
    values: &HashMap<String, String>,
    retired: &[(String, String)],
) -> Vec<Redaction> {
    let mut redactions: Vec<Redaction> = Vec::new();
    let current = values
        .iter()
        .map(|(secret, value)| (secret.as_str(), value.as_str()));
    let retired = retired
        .iter()
        .map(|(secret, value)| (secret.as_str(), value.as_str()));
    for (secret, value) in current.chain(retired) {
        for rule in rules.iter().filter(|rule| rule.secret == secret) {
            match redactions
                .iter_mut()
                .find(|redaction| redaction.value == value.as_bytes())
            {
                Some(existing) => existing.lenient |= rule.lenient,
                None => redactions.push(Redaction {
                    value: value.as_bytes().to_vec(),
                    placeholder: rule.placeholder.as_bytes().to_vec(),
                    lenient: rule.lenient,
                }),
            }
        }
    }
    redactions.sort_by_key(|redaction| std::cmp::Reverse(redaction.value.len()));
    redactions
}
