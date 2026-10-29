//! Leases that rules name instead of secrets. The proxy mints a lease the
//! first time a request carries one of its placeholders, shares it across
//! requests while it is valid, mints a new one shortly before it expires,
//! and revokes every lease it minted when the session ends.
//!
//! Minted leases are recorded in the project's lease ledger without their
//! credentials, so `fnox lease list` and `fnox lease revoke` see them, but
//! `fnox exec` never reuses a credential meant only for the proxy. The proxy
//! never reuses a lease another command cached either: that value has been in
//! a child's environment.

use super::*;
use crate::lease::{self, LeaseLedger};
use crate::lease_backends::{Lease, LeaseBackend, LeaseBackendConfig};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long minting or revoking one lease may take
const LEASE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long after a failed mint a request may try again
const MINT_RETRY: Duration = Duration::from_secs(10);

/// Renew a lease when this much of it is left, or a quarter of its lifetime
/// if that is shorter
const RENEW_BEFORE: Duration = Duration::from_secs(lease::LEASE_REUSE_BUFFER_SECS as u64);

/// The variable a lease rule injects: its `credential`, or the only variable
/// its lease produces
pub fn lease_credential(
    rule: &ProxyRule,
    name: &str,
    config: &LeaseBackendConfig,
) -> Result<String> {
    if matches!(config, LeaseBackendConfig::AwsSts { .. }) {
        return Err(proxy_error(format!(
            "lease '{name}' is an aws-sts lease, whose credentials sign requests; a rule can only substitute a header or query value"
        )));
    }
    let produced = config.produced_env_vars();
    match &rule.credential {
        // A lease whose variables aren't known until it runs (a `command`
        // lease) is checked when it is minted
        Some(credential) if produced.is_empty() || produced.contains(&credential.as_str()) => {
            Ok(credential.clone())
        }
        Some(credential) => Err(proxy_error(format!(
            "lease '{name}' doesn't produce '{credential}'; it produces {}",
            produced.join(", ")
        ))),
        None => match produced.as_slice() {
            [only] => Ok(only.to_string()),
            [] => Err(proxy_error(format!(
                "rule for lease '{name}' needs `credential`, the variable to inject, because the lease's variables aren't known until it runs"
            ))),
            several => Err(proxy_error(format!(
                "lease '{name}' produces several variables ({}); set `credential` on the rule to pick one",
                several.join(", ")
            ))),
        },
    }
}

/// The leases a proxy's rules name
#[derive(Default)]
pub(super) struct ProxyLeases {
    slots: HashMap<String, LeaseSlot>,
    /// The project directory whose lease ledger records minted leases
    ledger: Option<PathBuf>,
    /// Set when the session ends: nothing is minted after that
    closed: AtomicBool,
}

impl std::fmt::Debug for ProxyLeases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyLeases")
            .field("leases", &self.slots.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

struct LeaseSlot {
    backend: Arc<dyn LeaseBackend>,
    duration: Duration,
    config_hash: String,
    /// The variables rules inject
    credentials: Vec<String>,
    /// Held while a lease is minted, so concurrent requests share one
    state: tokio::sync::Mutex<SlotState>,
    /// Why the last mint failed, for the requests it refuses
    failure: std::sync::Mutex<Option<String>>,
}

#[derive(Default)]
struct SlotState {
    /// When the lease in use expires, if it does
    expires_at: Option<DateTime<Utc>>,
    /// When to mint the next one; `None` while no lease is in use
    renew_at: Option<RenewAt>,
    last_failure: Option<Instant>,
    /// Every lease minted this session, to revoke when it ends
    minted: Vec<Lease>,
}

#[derive(Clone, Copy)]
enum RenewAt {
    Never,
    At(DateTime<Utc>),
}

impl ProxyLeases {
    /// Prepare the leases `leases` names. `credentials` lists the variables
    /// rules inject from each.
    pub(super) fn new(
        leases: &IndexMap<String, LeaseBackendConfig>,
        credentials: &IndexMap<String, Vec<String>>,
        ledger: Option<PathBuf>,
    ) -> Result<Self> {
        let mut slots = HashMap::new();
        for (name, credentials) in credentials {
            let config = leases
                .get(name)
                .ok_or_else(|| proxy_error(format!("rule references unknown lease '{name}'")))?;
            let backend: Arc<dyn LeaseBackend> = config.create_backend()?.into();
            let duration_str = config.duration().unwrap_or(lease::DEFAULT_LEASE_DURATION);
            let duration = lease::parse_duration(duration_str)?;
            if duration > backend.max_lease_duration() {
                return Err(proxy_error(format!(
                    "lease duration '{duration_str}' for '{name}' exceeds maximum {:?}",
                    backend.max_lease_duration()
                )));
            }
            slots.insert(
                name.clone(),
                LeaseSlot::new(backend, duration, config.config_hash(), credentials.clone()),
            );
        }
        Ok(Self {
            slots,
            ledger,
            closed: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    pub(super) fn insert(
        &mut self,
        name: &str,
        backend: Arc<dyn LeaseBackend>,
        credentials: &[&str],
    ) {
        self.slots.insert(
            name.to_string(),
            LeaseSlot::new(
                backend,
                Duration::from_secs(3600),
                String::new(),
                credentials.iter().map(|c| c.to_string()).collect(),
            ),
        );
    }

    /// Mint the leases among `names` that have no usable credential, or that
    /// are due for renewal
    pub(super) async fn ensure(&self, names: &[&str], values: &SecretValues) {
        let mut seen = HashSet::new();
        for name in names {
            if !seen.insert(*name) {
                continue;
            }
            if let Some(slot) = self.slots.get(*name) {
                slot.ensure(name, values, &self.closed, self.ledger.as_deref())
                    .await;
            }
        }
    }

    /// Why a request that needs `name` can't have its credential
    pub(super) fn unavailable(&self, name: &str) -> FnoxError {
        let failure = self.slots.get(name).and_then(|slot| {
            slot.failure
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        });
        match failure {
            Some(reason) => proxy_error(format!(
                "lease '{name}' could not be minted: {reason}; a later request tries again"
            )),
            None if self.closed.load(Ordering::SeqCst) => proxy_error(format!(
                "lease '{name}' is not available because the session is ending"
            )),
            None => proxy_error(format!("lease '{name}' has no credential yet; retry")),
        }
    }

    /// Stop injecting and minting leases, and revoke every lease minted this
    /// session, for backends that support revocation. A lease the backend
    /// couldn't revoke stays active in the ledger, for `fnox lease revoke` or
    /// `fnox lease cleanup`.
    pub(super) async fn revoke_all(&self, values: &SecretValues) {
        self.closed.store(true, Ordering::SeqCst);
        let mut revoked = Vec::new();
        for (name, slot) in &self.slots {
            // Waits for a mint in flight, so its lease is revoked too
            let state = slot.state.lock().await;
            for credential in &slot.credentials {
                values.forget(&LeaseSlot::source(name, credential));
            }
            for minted in &state.minted {
                let expired = minted.expires_at.is_some_and(|at| at <= Utc::now());
                let revoke = slot
                    .backend
                    .revoke_lease(&minted.lease_id, Some(&minted.credentials));
                match tokio::time::timeout(LEASE_TIMEOUT, revoke).await {
                    Ok(Ok(())) => {
                        tracing::debug!("fnox proxy: revoked lease '{}'", minted.lease_id);
                        revoked.push(minted.lease_id.clone());
                    }
                    // It is no longer valid anyway
                    _ if expired => revoked.push(minted.lease_id.clone()),
                    Ok(Err(error)) => tracing::warn!(
                        "fnox proxy: could not revoke lease '{}' of '{name}': {error}; run `fnox lease revoke {}` to retry",
                        minted.lease_id,
                        minted.lease_id
                    ),
                    Err(_) => tracing::warn!(
                        "fnox proxy: revoking lease '{}' of '{name}' took longer than {}s; run `fnox lease revoke {}` to retry",
                        minted.lease_id,
                        LEASE_TIMEOUT.as_secs(),
                        minted.lease_id
                    ),
                }
            }
        }
        if revoked.is_empty() {
            return;
        }
        if let Some(project_dir) = &self.ledger {
            let marked = (|| -> Result<()> {
                let _lock = LeaseLedger::lock(project_dir)?;
                let mut ledger = LeaseLedger::load(project_dir)?;
                for lease_id in &revoked {
                    ledger.mark_revoked(lease_id);
                }
                ledger.save(project_dir)
            })();
            if let Err(error) = marked {
                tracing::warn!("fnox proxy: could not mark revoked leases in the ledger: {error}");
            }
        }
    }
}

impl LeaseSlot {
    fn new(
        backend: Arc<dyn LeaseBackend>,
        duration: Duration,
        config_hash: String,
        credentials: Vec<String>,
    ) -> Self {
        Self {
            backend,
            duration,
            config_hash,
            credentials,
            state: tokio::sync::Mutex::new(SlotState::default()),
            failure: std::sync::Mutex::new(None),
        }
    }

    fn source(name: &str, credential: &str) -> Source {
        Source::Lease {
            lease: name.to_string(),
            credential: credential.to_string(),
        }
    }

    async fn ensure(
        &self,
        name: &str,
        values: &SecretValues,
        closed: &AtomicBool,
        ledger: Option<&std::path::Path>,
    ) {
        if closed.load(Ordering::SeqCst) {
            return;
        }
        let mut state = self.state.lock().await;
        // The session may have ended while this waited for another mint
        if closed.load(Ordering::SeqCst) {
            return;
        }
        let now = Utc::now();
        match state.renew_at {
            Some(RenewAt::Never) => return,
            Some(RenewAt::At(at)) if now < at => return,
            _ => {}
        }
        // An expired credential is never injected, even if renewing fails
        if state.expires_at.is_some_and(|at| at <= now) {
            for credential in &self.credentials {
                values.forget(&Self::source(name, credential));
            }
            state.expires_at = None;
            state.renew_at = None;
        }
        if state
            .last_failure
            .is_some_and(|at| at.elapsed() < MINT_RETRY)
        {
            return;
        }
        match self.mint(name, values, &mut state, ledger).await {
            Ok(()) => {
                state.last_failure = None;
                *self.failure.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }
            Err(error) => {
                tracing::warn!("fnox proxy: could not mint lease '{name}': {error}");
                state.last_failure = Some(Instant::now());
                *self.failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
            }
        }
    }

    async fn mint(
        &self,
        name: &str,
        values: &SecretValues,
        state: &mut SlotState,
        ledger: Option<&std::path::Path>,
    ) -> Result<()> {
        let label = format!("fnox-proxy-{name}");
        let minted_at = Utc::now();
        let lease = tokio::time::timeout(
            LEASE_TIMEOUT,
            self.backend.create_lease(self.duration, &label),
        )
        .await
        .map_err(|_| proxy_error(format!("took longer than {}s", LEASE_TIMEOUT.as_secs())))??;
        if let Some(project_dir) = ledger {
            self.record(name, &label, &lease, project_dir);
        }
        state.minted.push(lease.clone());

        // Every credential is checked before any is used, so requests never
        // mix credentials of two leases
        let mut found = Vec::new();
        for credential in &self.credentials {
            let source = Self::source(name, credential);
            let value = lease.credentials.get(credential).ok_or_else(|| {
                proxy_error(format!(
                    "the lease has no '{credential}'; it produced {}",
                    lease
                        .credentials
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
            values.validate(&source, value)?;
            found.push((source, value.clone()));
        }
        for (source, value) in found {
            values.replace(&source, value)?;
        }
        state.expires_at = lease.expires_at;
        state.renew_at = Some(renew_at(minted_at, lease.expires_at));
        tracing::info!(
            target: "fnox::proxy",
            lease = name,
            lease_id = lease.lease_id.as_str(),
            expires_at = ?lease.expires_at,
            "minted lease"
        );
        Ok(())
    }

    /// Record a minted lease in the ledger, without its credentials
    fn record(&self, name: &str, label: &str, lease: &Lease, project_dir: &std::path::Path) {
        let recorded = LeaseLedger::lock(project_dir).and_then(|_lock| {
            let mut ledger = LeaseLedger::load(project_dir)?;
            lease::record_lease(
                &mut ledger,
                lease,
                name,
                label,
                self.config_hash.clone(),
                None,
                None,
                project_dir,
            );
            Ok(())
        });
        if let Err(error) = recorded {
            tracing::warn!(
                "fnox proxy: lease '{}' of '{name}' is not in the ledger: {error}",
                lease.lease_id
            );
        }
    }
}

/// When to replace a lease minted at `minted_at`: [`RENEW_BEFORE`] before it
/// expires, or after three quarters of its lifetime if that is sooner
fn renew_at(minted_at: DateTime<Utc>, expires_at: Option<DateTime<Utc>>) -> RenewAt {
    let Some(expires_at) = expires_at else {
        return RenewAt::Never;
    };
    let lifetime = (expires_at - minted_at).to_std().unwrap_or_default();
    let before = RENEW_BEFORE.min(lifetime / 4);
    RenewAt::At(expires_at - chrono::Duration::from_std(before).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renews_before_expiry() {
        let minted = Utc::now();
        let at = |lifetime: i64| match renew_at(
            minted,
            Some(minted + chrono::Duration::seconds(lifetime)),
        ) {
            RenewAt::At(at) => (at - minted).num_seconds(),
            RenewAt::Never => -1,
        };
        // Five minutes early for a long lease, a quarter early for a short one
        assert_eq!(at(3600), 3300);
        assert_eq!(at(400), 300);
        assert!(matches!(renew_at(minted, None), RenewAt::Never));
    }
}
