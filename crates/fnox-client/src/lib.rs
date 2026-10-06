//! A read-only client for the fnox daemon, and the types of `fnox env --json`.
//!
//! This crate lets another program ask a running fnox daemon for the
//! environment a command would get, in one round trip over a Unix socket and
//! with no fnox process. It depends on neither fnox-core nor tokio, so it pulls
//! in none of the provider SDKs.
//!
//! The client only reads. It never starts the daemon, never stores values in
//! it, and never makes it call a provider. On a cache miss it says so, and the
//! caller runs `fnox env --json` itself.
//!
//! ```no_run
//! use fnox_client::{Client, CliFlags, EnvOutcome, EnvRequest, RuntimeEnv, SocketKey};
//! use fnox_client::document::EnvScope;
//! use std::path::Path;
//!
//! let env: Vec<(String, String)> = std::env::vars().collect();
//! let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
//! let key = SocketKey::from_cli_env(&CliFlags::default(), &get);
//! let client = Client::new(key, &RuntimeEnv::from_env(&get));
//! let keys = vec!["DATABASE_URL".to_string()];
//! let outcome = client.resolve_env(&EnvRequest {
//!     cwd: Path::new("/path/to/project"),
//!     config: Path::new("fnox.toml"),
//!     scope: EnvScope::Exec,
//!     keys: Some(&keys),
//!     env: &env,
//! });
//! if let EnvOutcome::Hit(document) = outcome {
//!     for (name, value) in &document.set {
//!         let _ = (name, value.expose());
//!     }
//! }
//! ```
//!
//! Semver covers [`Client`], [`EnvRequest`], [`EnvOutcome`], [`HelloInfo`],
//! [`CallError`], [`CliFlags`], [`SocketKey`], [`RuntimeEnv`], [`document`],
//! [`profile`], [`platform_supported`] and [`daemon_env_override`]. [`wire`],
//! [`path`] and [`peer`] are shared with the fnox daemon and change along with
//! [`WIRE_VERSION`].

mod client;
pub mod document;
mod error;
pub mod path;
#[cfg(unix)]
#[doc(hidden)]
pub mod peer;
pub mod profile;
#[doc(hidden)]
pub mod wire;

pub use client::{Client, EnvOutcome, EnvRequest, HelloInfo};
pub use error::CallError;
pub use path::{CliFlags, RuntimeEnv, SocketKey};

/// The protocol version this crate speaks. It is part of the socket name, so a
/// client never connects to a daemon with an incompatible wire format.
///
/// Version 4 requires missing values to remain cache misses, including after upgrades.
/// Version 5 adds keyed clears and rejects foreground write-backs for keys cleared
/// while they were being resolved.
/// Version 6 adds `hello` and `resolve_env`, and length-prefixes the socket hash fields.
pub const WIRE_VERSION: u8 = 6;

/// The oldest protocol this crate talks to.
pub const MIN_PROTOCOL: u32 = 6;

/// Whether fnox's daemon runs on this platform: Linux, macOS, FreeBSD and OpenBSD.
pub const fn platform_supported() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd"
    ))
}

/// What `FNOX_DAEMON` says: `0`, `false`, `off` or `no` is `Some(false)`; `1`,
/// `true`, `on` or `yes` is `Some(true)`; anything else, or unset, is `None`.
pub fn daemon_env_override(get: &dyn Fn(&str) -> Option<String>) -> Option<bool> {
    match get("FNOX_DAEMON").as_deref() {
        Some("0" | "false" | "off" | "no") => Some(false),
        Some("1" | "true" | "on" | "yes") => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_env_override_truth_table() {
        let with = |value: Option<&str>| {
            let value = value.map(String::from);
            daemon_env_override(&move |k| {
                assert_eq!(k, "FNOX_DAEMON");
                value.clone()
            })
        };
        for off in ["0", "false", "off", "no"] {
            assert_eq!(with(Some(off)), Some(false), "{off}");
        }
        for on in ["1", "true", "on", "yes"] {
            assert_eq!(with(Some(on)), Some(true), "{on}");
        }
        for other in ["", "maybe", "OFF", "True", " 1", "2"] {
            assert_eq!(with(Some(other)), None, "{other:?}");
        }
        assert_eq!(with(None), None);
    }

    #[test]
    fn protocol_constants_agree() {
        assert_eq!(u32::from(WIRE_VERSION), MIN_PROTOCOL);
    }
}
