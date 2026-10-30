//! Credentials from `[leases]` that rules inject. The proxy creates a lease
//! the first time a request needs it, shares it across requests while it is
//! valid, and revokes every lease it created when the session ends.

use super::*;
use crate::lease_backends::Lease;
use std::time::{Duration, Instant};

/// A lease this close to expiring is replaced before a request uses it
const REUSE_MARGIN_SECS: i64 = 30;

/// How often a lease that could not be created may be tried again
const MINT_RETRY: Duration = Duration::from_secs(3);

pub type MintFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Creates and revokes the leases rules name
pub trait LeaseMinter: Send + Sync {
    /// Create a lease from the backend named `lease`
    fn mint<'a>(&'a self, lease: &'a str) -> MintFuture<'a, Lease>;

    /// Revoke a lease that [`Self::mint`] created
    fn revoke<'a>(&'a self, lease: &'a str, minted: &'a Lease) -> MintFuture<'a, ()>;
}

#[derive(Default)]
struct Slot {
    current: Option<Lease>,
    failed_at: Option<Instant>,
}

struct Entry {
    /// The variable of the lease that rules inject
    credential: String,
    /// The lease's key in [`SecretValues`]
    value_name: String,
    /// Held while minting, so concurrent requests create one lease, not one
    /// each (a GitLab lease creates a bot user per token)
    slot: tokio::sync::Mutex<Slot>,
}

pub struct ProxyLeases {
    entries: HashMap<String, Entry>,
    /// Every lease created this session, revoked when it ends
    minted: std::sync::Mutex<Vec<(String, Lease)>>,
    minter: std::sync::OnceLock<Arc<dyn LeaseMinter>>,
}

impl std::fmt::Debug for ProxyLeases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyLeases")
            .field("leases", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ProxyLeases {
    /// `credentials` maps each lease rules name to the variable they inject
    pub(super) fn new(credentials: HashMap<String, String>) -> Self {
        let entries = credentials
            .into_iter()
            .map(|(lease, credential)| {
                let entry = Entry {
                    credential,
                    value_name: format!("lease:{lease}"),
                    slot: tokio::sync::Mutex::default(),
                };
                (lease, entry)
            })
            .collect();
        Self {
            entries,
            minted: std::sync::Mutex::default(),
            minter: std::sync::OnceLock::new(),
        }
    }

    pub(super) fn set_minter(&self, minter: Arc<dyn LeaseMinter>) {
        let _ = self.minter.set(minter);
    }

    /// Make sure each of `leases` has a value in `values` that is not about
    /// to expire, creating a lease if needed. A lease that fails is retried
    /// at most once per [`MINT_RETRY`].
    pub(super) async fn ensure(&self, values: &SecretValues, leases: &[&str]) {
        let Some(minter) = self.minter.get() else {
            return;
        };
        for name in leases {
            let Some(entry) = self.entries.get(*name) else {
                continue;
            };
            let mut slot = entry.slot.lock().await;
            let now = chrono::Utc::now();
            if let Some(current) = &slot.current {
                let expires = current.expires_at;
                if expires.is_none_or(|at| at - chrono::Duration::seconds(REUSE_MARGIN_SECS) > now)
                {
                    continue;
                }
                if expires.is_some_and(|at| at <= now) {
                    values.forget(&entry.value_name);
                    slot.current = None;
                }
            }
            if slot
                .failed_at
                .is_some_and(|failed| failed.elapsed() < MINT_RETRY)
            {
                continue;
            }
            let lease = match minter.mint(name).await {
                Ok(lease) => lease,
                Err(error) => {
                    tracing::warn!("fnox proxy: could not create lease '{name}': {error}");
                    slot.failed_at = Some(Instant::now());
                    continue;
                }
            };
            // Recorded before any check, so even a lease that can't be used
            // is revoked at the end
            self.minted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((name.to_string(), lease.clone()));
            let used = match lease.credentials.get(&entry.credential) {
                Some(value) => values.replace(&entry.value_name, value.clone()),
                None => Err(proxy_error(format!(
                    "lease '{name}' did not produce '{}'",
                    entry.credential
                ))),
            };
            match used {
                Ok(()) => {
                    tracing::info!(
                        target: "fnox::proxy",
                        lease = *name,
                        lease_id = lease.lease_id.as_str(),
                        "created lease"
                    );
                    slot.current = Some(lease);
                    slot.failed_at = None;
                }
                Err(error) => {
                    tracing::warn!("fnox proxy: {error}");
                    slot.failed_at = Some(Instant::now());
                }
            }
        }
    }

    /// Revoke every lease created this session
    pub async fn revoke_all(&self) {
        let Some(minter) = self.minter.get() else {
            return;
        };
        let minted = std::mem::take(&mut *self.minted.lock().unwrap_or_else(|e| e.into_inner()));
        for (name, lease) in minted {
            match minter.revoke(&name, &lease).await {
                Ok(()) => tracing::info!(
                    target: "fnox::proxy",
                    lease = name.as_str(),
                    lease_id = lease.lease_id.as_str(),
                    "revoked lease"
                ),
                Err(error) => tracing::warn!(
                    "fnox proxy: could not revoke lease '{}' of '{name}': {error}; revoke it with `fnox lease revoke`",
                    lease.lease_id
                ),
            }
        }
    }

    #[cfg(test)]
    pub(super) fn retry_now(&self, lease: &str) {
        self.entries[lease]
            .slot
            .try_lock()
            .expect("no mint in flight")
            .failed_at = None;
    }
}
