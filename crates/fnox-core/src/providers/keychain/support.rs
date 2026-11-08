#[cfg(target_os = "macos")]
use crate::env;
use crate::error::{FnoxError, Result};

/// Run a blocking keyring call on tokio's blocking thread pool.
///
/// The OS keychain APIs are synchronous and may present a system dialog that
/// blocks until the user responds. Calling them directly on a tokio worker
/// thread pins that thread — concurrent calls can deadlock the runtime.
pub(super) async fn spawn_keychain_blocking<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| FnoxError::ProviderApiError {
            provider: "Keychain".to_string(),
            details: format!("Keychain task failed to complete: {e}"),
            hint: "This is a bug; please report it".to_string(),
            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
        })
}

pub(super) fn platform_backend_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "No OS keyring backend is available. Start a Secret Service provider \
         (e.g. gnome-keyring or KeePassXC) and make sure DBUS_SESSION_BUS_ADDRESS \
         is set."
    }
    #[cfg(target_os = "macos")]
    {
        "Failed to initialize the macOS Keychain backend."
    }
    #[cfg(target_os = "windows")]
    {
        "Failed to initialize the Windows Credential Manager backend."
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "The keychain provider is not supported on this platform."
    }
}

#[cfg(target_os = "macos")]
pub(super) fn invoking_command_cstring() -> std::ffi::CString {
    let executable = env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "fnox".to_string());
    let words = std::iter::once(executable)
        .chain(
            env::args_os()
                .skip(1)
                .map(|arg| arg.to_string_lossy().into_owned()),
        )
        .collect::<Vec<_>>();
    let command =
        shlex::try_join(words.iter().map(String::as_str)).unwrap_or_else(|_| words.join(" "));
    std::ffi::CString::new(command).expect("process arguments cannot contain NUL bytes")
}

#[cfg(target_os = "macos")]
pub(super) fn touch_id_error_hint(status: i32) -> &'static str {
    if status == -34018 {
        "This build lacks an Apple-authorized Keychain access group. Touch ID requires a macOS app bundle signed with a matching Developer ID provisioning profile and keychain-access-groups entitlement."
    } else {
        "Check that Touch ID is enrolled and approve the Fnox Keychain request"
    }
}
