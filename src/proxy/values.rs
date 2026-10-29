//! The real values of rule secrets. A secret that isn't set when the proxy
//! starts is pending: its placeholder is handed out, requests that need it are
//! refused, and the proxy resolves it again when a request needs it, so a
//! value set during the run starts working without a restart.

use super::*;
use std::time::{Duration, Instant};

use crate::secret_session::SecretSession;

/// How often a pending secret may be resolved again
const PENDING_RETRY: Duration = Duration::from_secs(3);

/// What a rule needs to redact its secret from responses
#[derive(Debug, Clone)]
pub(super) struct RuleRedaction {
    pub(super) secret: String,
    pub(super) placeholder: String,
    pub(super) lenient: bool,
}

#[derive(Debug, Default)]
struct State {
    values: HashMap<String, String>,
    redactions: Arc<Vec<Redaction>>,
}

#[derive(Debug)]
pub(super) struct SecretValues {
    rules: Vec<RuleRedaction>,
    state: std::sync::RwLock<State>,
    /// Where pending secrets are resolved from; without one they stay pending
    session: std::sync::OnceLock<Arc<SecretSession>>,
    /// Last time each pending secret was resolved again
    attempts: tokio::sync::Mutex<HashMap<String, Instant>>,
}

impl SecretValues {
    /// `values` holds the secrets that resolved at startup; every rule secret
    /// missing from it is pending
    pub(super) fn new(rules: Vec<RuleRedaction>, values: HashMap<String, String>) -> Self {
        let state = State {
            redactions: Arc::new(build_redactions(&rules, &values)),
            values,
        };
        Self {
            rules,
            state: std::sync::RwLock::new(state),
            session: std::sync::OnceLock::new(),
            attempts: tokio::sync::Mutex::new(HashMap::new()),
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
        for rule in &self.rules {
            if !state.values.contains_key(&rule.secret) && !pending.contains(&rule.secret) {
                pending.push(rule.secret.clone());
            }
        }
        pending
    }

    /// Use `value` for `secret` from now on, after the checks startup values
    /// get
    pub(super) fn set(&self, secret: &str, value: String) -> Result<()> {
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
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.values.insert(secret.to_string(), value);
        state.redactions = Arc::new(build_redactions(&self.rules, &state.values));
        Ok(())
    }

    /// Resolve the pending ones among `secrets` again, each at most once per
    /// [`PENDING_RETRY`], from the config as it is on disk now
    pub(super) async fn refresh(&self, secrets: &[&str]) {
        let Some(session) = self.session.get() else {
            return;
        };
        let pending: Vec<&str> = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            secrets
                .iter()
                .copied()
                .filter(|secret| !state.values.contains_key(*secret))
                .collect()
        };
        if pending.is_empty() {
            return;
        }
        let mut attempts = self.attempts.lock().await;
        let now = Instant::now();
        let due: Vec<&str> = pending
            .into_iter()
            .filter(|secret| {
                attempts
                    .get(*secret)
                    .is_none_or(|last| now.duration_since(*last) >= PENDING_RETRY)
            })
            .collect();
        if due.is_empty() {
            return;
        }
        let config = match session.load_config() {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!("fnox proxy: could not reload the config: {error}");
                return;
            }
        };
        for secret in due {
            attempts.insert(secret.to_string(), now);
            match session.load(&config, secret).await {
                Ok(true) => {
                    let Some(Some(value)) = session.cached(secret).await else {
                        continue;
                    };
                    match self.set(secret, value) {
                        Ok(()) => tracing::info!(
                            target: "fnox::proxy",
                            secret,
                            "pending secret is now set"
                        ),
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

/// One redaction per distinct value, longest first, so a value that contains
/// another is replaced whole
fn build_redactions(rules: &[RuleRedaction], values: &HashMap<String, String>) -> Vec<Redaction> {
    let mut redactions: Vec<Redaction> = Vec::new();
    for rule in rules {
        let Some(value) = values.get(&rule.secret) else {
            continue;
        };
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
    redactions.sort_by_key(|redaction| std::cmp::Reverse(redaction.value.len()));
    redactions
}
