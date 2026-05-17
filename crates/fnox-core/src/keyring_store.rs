//! Initialize the keyring-core default credential store once per process.
//!
//! `keyring-core` (the v4 successor to the old `keyring` crate) no longer
//! auto-selects a platform store via cargo features. Clients have to register
//! a store with `set_default_store` before creating any `Entry`. This module
//! does that lazily on first use so both the keychain provider and the
//! github_oauth lease backend can call `init()` without worrying about order.

use std::sync::Mutex;

// Only flips to `true` once `try_init` succeeds. A `Mutex<bool>` (rather than
// `std::sync::Once`) lets a transient failure — e.g. D-Bus not yet ready on
// Linux — be retried on the next call instead of being latched in for the
// process lifetime.
static INITIALIZED: Mutex<bool> = Mutex::new(false);

pub(crate) fn init() {
    let mut done = INITIALIZED
        .lock()
        .expect("keyring store init mutex poisoned");
    if *done {
        return;
    }
    match try_init() {
        Ok(()) => *done = true,
        Err(e) => tracing::warn!("Failed to initialize OS keyring store: {e}"),
    }
}

#[cfg(target_os = "macos")]
fn try_init() -> keyring_core::Result<()> {
    keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
    Ok(())
}

#[cfg(target_os = "windows")]
fn try_init() -> keyring_core::Result<()> {
    keyring_core::set_default_store(windows_native_keyring_store::Store::new()?);
    Ok(())
}

#[cfg(target_os = "linux")]
fn try_init() -> keyring_core::Result<()> {
    keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new()?);
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn try_init() -> keyring_core::Result<()> {
    Ok(())
}
