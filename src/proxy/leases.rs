//! Leases that rules name instead of secrets. The proxy mints a lease the
//! first time a request carries one of its placeholders, shares it across
//! requests while it is valid, mints a new one shortly before it expires,
//! and revokes every lease it minted when the session ends.
//!
//! Minted leases are recorded in the project's lease ledger, so `fnox lease
//! list` and `fnox lease revoke` see them. The ledger keeps their credentials,
//! encrypted, only for revoking them: `fnox exec` never reuses a credential
//! meant only for the proxy. The proxy never reuses a lease another command
//! cached either: that value has been in a child's environment.

use super::*;
use crate::lease::{self, LeaseLedger, LeaseRecord};
use crate::lease_backends::{Lease, LeaseBackend, LeaseBackendConfig};
use crate::providers::Provider;
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long minting or revoking one lease may take, unless a `command`
/// lease's own timeout is longer
const LEASE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long encrypting a minted lease's credentials for the ledger may take
const ENCRYPT_TIMEOUT: Duration = Duration::from_secs(5);

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

/// What the proxy needs to record the leases it mints and keep their
/// parent credentials out of its messages
#[derive(Default)]
pub struct LeaseSetup {
    /// The project directory whose lease ledger records minted leases
    pub ledger: Option<PathBuf>,
    /// The encryption provider, by name, that encrypts the credentials the
    /// ledger keeps to revoke a lease later. Without one none are kept.
    pub encryption: Option<(String, Arc<dyn Provider>)>,
    /// Values, such as the leases' parent credentials, removed from errors
    /// before they are logged
    pub hidden: Vec<String>,
}

/// The leases a proxy's rules name
#[derive(Default)]
pub(super) struct ProxyLeases {
    slots: HashMap<String, LeaseSlot>,
    setup: LeaseSetup,
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
    /// How long minting or revoking one lease may take
    timeout: Duration,
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
    minted: Vec<Minted>,
}

struct Minted {
    lease: Lease,
    /// Its ledger record's `created_at`, which tells it apart from another
    /// record with the same lease ID
    recorded_at: DateTime<Utc>,
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
        setup: LeaseSetup,
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
            // A `command` lease's own timeout reports a slow command better,
            // so leave it room to fire first
            let timeout = match config {
                LeaseBackendConfig::Command { timeout, .. } => {
                    LEASE_TIMEOUT.max(lease::parse_duration(timeout)? + Duration::from_secs(5))
                }
                _ => LEASE_TIMEOUT,
            };
            slots.insert(
                name.clone(),
                LeaseSlot {
                    backend,
                    duration,
                    timeout,
                    config_hash: config.config_hash(),
                    credentials: credentials.clone(),
                    state: tokio::sync::Mutex::new(SlotState::default()),
                    failure: std::sync::Mutex::new(None),
                },
            );
        }
        Ok(Self {
            slots,
            setup,
            closed: AtomicBool::new(false),
        })
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
                slot.ensure(name, values, &self.closed, &self.setup).await;
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
        if let Some(reason) = failure {
            proxy_error(format!(
                "lease '{name}' could not be minted: {reason}; a later request tries again"
            ))
        } else if self.closed.load(Ordering::SeqCst) {
            proxy_error(format!(
                "lease '{name}' is not available because the session is ending"
            ))
        } else {
            proxy_error(format!("lease '{name}' has no credential yet; retry"))
        }
    }

    /// Stop injecting and minting leases, and revoke every lease minted this
    /// session, for backends that support revocation. A lease the backend
    /// couldn't revoke stays active in the ledger, for `fnox lease revoke` or
    /// `fnox lease cleanup`.
    pub(super) async fn revoke_all(&self, values: &SecretValues) {
        self.closed.store(true, Ordering::SeqCst);
        let mut revoked: Vec<(&str, String, DateTime<Utc>)> = Vec::new();
        for (name, slot) in &self.slots {
            // Waits for a mint in flight, so its lease is revoked too
            let state = slot.state.lock().await;
            for credential in &slot.credentials {
                values.forget(&source(name, credential));
            }
            for minted in &state.minted {
                let lease = &minted.lease;
                let expired = lease.expires_at.is_some_and(|at| at <= Utc::now());
                let revoke = slot
                    .backend
                    .revoke_lease(&lease.lease_id, Some(&lease.credentials));
                match tokio::time::timeout(slot.timeout, revoke).await {
                    Ok(Ok(())) => {
                        tracing::debug!("fnox proxy: revoked lease '{}'", lease.lease_id);
                        revoked.push((name, lease.lease_id.clone(), minted.recorded_at));
                    }
                    // It is no longer valid anyway
                    _ if expired => {
                        revoked.push((name, lease.lease_id.clone(), minted.recorded_at))
                    }
                    Ok(Err(error)) => tracing::warn!(
                        "fnox proxy: could not revoke lease '{}' of '{name}': {}; run `fnox lease revoke {}` to retry",
                        lease.lease_id,
                        self.setup.scrub(&error.to_string()),
                        lease.lease_id
                    ),
                    Err(_) => tracing::warn!(
                        "fnox proxy: revoking lease '{}' of '{name}' took longer than {}s; run `fnox lease revoke {}` to retry",
                        lease.lease_id,
                        slot.timeout.as_secs(),
                        lease.lease_id
                    ),
                }
            }
        }
        if revoked.is_empty() {
            return;
        }
        if let Some(project_dir) = &self.setup.ledger {
            let marked = (|| -> Result<()> {
                let _lock = LeaseLedger::lock(project_dir)?;
                let mut ledger = LeaseLedger::load(project_dir)?;
                // By backend, ID and creation time: lease IDs need not be
                // unique, even within one backend
                for (name, lease_id, recorded_at) in &revoked {
                    if let Some(index) = ledger.leases.iter().position(|record| {
                        !record.revoked
                            && record.backend_name == *name
                            && record.lease_id == *lease_id
                            && record.created_at == *recorded_at
                    }) {
                        ledger.mark_revoked_at(index);
                    }
                }
                ledger.save(project_dir)
            })();
            if let Err(error) = marked {
                tracing::warn!("fnox proxy: could not mark revoked leases in the ledger: {error}");
            }
        }
    }
}

/// Why minting a lease failed
enum MintError {
    /// The backend failed. Its error can quote a parent credential, such as a
    /// `command` lease's stderr, so it goes only to fnox's log, scrubbed.
    Backend(FnoxError),
    /// fnox can't use the lease it got, for this reason
    Unusable(String),
}

impl MintError {
    /// One of fnox's own checks refused the lease
    fn unusable(error: FnoxError) -> Self {
        Self::Unusable(match error {
            FnoxError::Config(message) => message.trim_start_matches("proxy: ").to_string(),
            other => other.to_string(),
        })
    }
}

impl LeaseSetup {
    /// `message` without the hidden values
    fn scrub(&self, message: &str) -> String {
        let mut message = message.to_string();
        for value in &self.hidden {
            if let Some(value) = crate::redact::redactable(value) {
                message = message.replace(value, crate::redact::MARKER);
            }
        }
        message
    }
}

fn source(name: &str, credential: &str) -> Source {
    Source::Lease {
        lease: name.to_string(),
        credential: credential.to_string(),
    }
}

impl LeaseSlot {
    async fn ensure(
        &self,
        name: &str,
        values: &SecretValues,
        closed: &AtomicBool,
        setup: &LeaseSetup,
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
        let due = state
            .last_failure
            .is_none_or(|at| at.elapsed() >= MINT_RETRY);
        if due {
            let failure = match self.mint(name, values, &mut state, setup).await {
                Ok(()) => None,
                Err(MintError::Backend(error)) => {
                    tracing::warn!(
                        "fnox proxy: could not mint lease '{name}': {}",
                        setup.scrub(&error.to_string())
                    );
                    Some("the lease backend failed, and fnox's log has its error".to_string())
                }
                Err(MintError::Unusable(reason)) => {
                    tracing::warn!("fnox proxy: could not mint lease '{name}': {reason}");
                    Some(reason)
                }
            };
            state.last_failure = failure.is_some().then(Instant::now);
            *self.failure.lock().unwrap_or_else(|e| e.into_inner()) = failure;
        }
        // An expired credential is never injected, including one whose
        // renewal just failed
        if state.expires_at.is_some_and(|at| at <= Utc::now()) {
            for credential in &self.credentials {
                values.forget(&source(name, credential));
            }
            state.expires_at = None;
            state.renew_at = None;
        }
    }

    async fn mint(
        &self,
        name: &str,
        values: &SecretValues,
        state: &mut SlotState,
        setup: &LeaseSetup,
    ) -> std::result::Result<(), MintError> {
        let label = format!("fnox-proxy-{name}");
        let minted_at = Utc::now();
        let lease = tokio::time::timeout(
            self.timeout,
            self.backend.create_lease(self.duration, &label),
        )
        .await
        .map_err(|_| {
            MintError::Unusable(format!("it took longer than {}s", self.timeout.as_secs()))
        })?
        .map_err(MintError::Backend)?;
        let recorded_at = Utc::now();
        if let Some(project_dir) = &setup.ledger {
            self.record(name, &label, &lease, recorded_at, setup, project_dir)
                .await;
        }
        state.minted.push(Minted {
            lease: lease.clone(),
            recorded_at,
        });

        if lease.expires_at.is_some_and(|at| at <= Utc::now()) {
            return Err(MintError::Unusable(
                "the lease had already expired when it was minted".to_string(),
            ));
        }
        // Every credential is checked before any is used, so requests never
        // mix credentials of two leases
        let mut found = Vec::new();
        for credential in &self.credentials {
            let source = source(name, credential);
            let value = lease.credentials.get(credential).ok_or_else(|| {
                MintError::Unusable(format!(
                    "the lease has no '{credential}'; it produced {}",
                    lease
                        .credentials
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
            values
                .validate(&source, value)
                .map_err(MintError::unusable)?;
            found.push((source, value.clone()));
        }
        for (source, value) in found {
            values
                .replace(&source, value)
                .map_err(MintError::unusable)?;
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

    /// Record a minted lease in the ledger. Its credentials are kept, if an
    /// encryption provider can encrypt them, only to revoke it later: the
    /// record never offers them to a command.
    async fn record(
        &self,
        name: &str,
        label: &str,
        lease: &Lease,
        recorded_at: DateTime<Utc>,
        setup: &LeaseSetup,
        project_dir: &std::path::Path,
    ) {
        // Optional, so bounded: a provider that waits for a PIN or a key
        // touch must not hold up requests, or revocation at shutdown, which
        // waits for this lease's lock
        let (revoke_credentials, encryption_provider) = match &setup.encryption {
            Some((provider_name, provider)) => {
                let encrypt = lease::encrypt_credentials(provider.as_ref(), &lease.credentials);
                let encrypted = match tokio::time::timeout(ENCRYPT_TIMEOUT, encrypt).await {
                    Ok(Ok(encrypted)) => Ok(encrypted),
                    Ok(Err(error)) => Err(setup.scrub(&error.to_string())),
                    Err(_) => Err(format!(
                        "encrypting its credentials took longer than {}s",
                        ENCRYPT_TIMEOUT.as_secs()
                    )),
                };
                match encrypted {
                    Ok(encrypted) => (Some(encrypted), Some(provider_name.clone())),
                    Err(reason) => {
                        tracing::warn!(
                            "fnox proxy: lease '{}' of '{name}' can't be revoked after this session if fnox can't revoke it now: {reason}",
                            lease.lease_id
                        );
                        (None, None)
                    }
                }
            }
            None => (None, None),
        };
        let recorded = LeaseLedger::lock(project_dir).and_then(|_lock| {
            let mut ledger = LeaseLedger::load(project_dir)?;
            ledger.add(LeaseRecord {
                lease_id: lease.lease_id.clone(),
                backend_name: name.to_string(),
                label: label.to_string(),
                created_at: recorded_at,
                expires_at: lease.expires_at,
                revoked: false,
                cached_credentials: None,
                encryption_provider,
                revoke_credentials,
                config_hash: Some(self.config_hash.clone()),
            });
            ledger.save(project_dir)
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
    fn a_command_lease_keeps_its_own_longer_timeout() {
        let timeout = |toml: &str| {
            let leases: IndexMap<String, LeaseBackendConfig> =
                toml_edit::de::from_str(toml).unwrap();
            let credentials = [("forge".to_string(), vec!["TOKEN".to_string()])].into();
            let leases = ProxyLeases::new(&leases, &credentials, LeaseSetup::default()).unwrap();
            leases.slots["forge"].timeout
        };
        let command = "[forge]\ntype = \"command\"\ncreate_command = \"true\"\n";
        // Its default of 30s, plus room for it to fire first
        assert_eq!(timeout(command), Duration::from_secs(35));
        let gitlab = "[forge]\ntype = \"gitlab\"\nproject = \"team/app\"\n";
        assert_eq!(timeout(gitlab), LEASE_TIMEOUT);
        assert_eq!(
            timeout(&format!("{command}timeout = \"2m\"\n")),
            Duration::from_secs(125)
        );
    }

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
