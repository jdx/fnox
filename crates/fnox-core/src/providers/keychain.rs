use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use keyring_core::Entry;
use std::collections::HashMap;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

pub struct KeychainProvider {
    service: String,
    prefix: Option<String>,
    touch_id: bool,
}

impl KeychainProvider {
    pub fn new(service: String, prefix: Option<String>, touch_id: bool) -> Result<Self> {
        if touch_id && !cfg!(target_os = "macos") {
            return Err(FnoxError::Provider(
                "The keychain provider's touch_id option is supported only on macOS".to_string(),
            ));
        }
        Ok(Self {
            service,
            prefix,
            touch_id,
        })
    }

    /// Build the full key name with optional prefix
    fn build_key_name(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}{}", prefix, key),
            None => key.to_string(),
        }
    }

    /// Create a keyring entry
    fn create_entry(&self, key: &str) -> Result<Entry> {
        crate::keyring_store::init();
        let full_key = self.build_key_name(key);
        let service = self.effective_service();
        Entry::new(&service, &full_key).map_err(|e| match e {
            // `Entry::new` itself fails with `NoDefaultStore` when the platform
            // backend couldn't be registered (e.g. headless Linux without
            // Secret Service). Surface a backend-specific hint here, since the
            // call never reaches `get_password`/`set_password`.
            keyring_core::Error::NoDefaultStore => FnoxError::ProviderAuthFailed {
                provider: "Keychain".to_string(),
                details: e.to_string(),
                hint: platform_backend_hint().to_string(),
                url: "https://fnox.jdx.dev/providers/keychain".to_string(),
            },
            _ => FnoxError::ProviderApiError {
                provider: "Keychain".to_string(),
                details: format!(
                    "Failed to create entry for service '{}', key '{}': {}",
                    self.service, full_key, e
                ),
                hint: "Check that the keychain is accessible".to_string(),
                url: "https://fnox.jdx.dev/providers/keychain".to_string(),
            },
        })
    }

    fn effective_service(&self) -> String {
        if self.touch_id {
            format!("{}.touch-id", self.service)
        } else {
            self.service.clone()
        }
    }

    /// Store a secret in the OS keychain.
    ///
    /// The underlying `keyring-core` call is synchronous and on macOS may
    /// present a Security framework dialog that blocks until the user
    /// responds. We run it on a blocking thread pool so the tokio runtime
    /// keeps making progress (and so concurrent calls don't pin every worker
    /// thread).
    pub async fn put_secret(&self, key: &str, value: &str) -> Result<()> {
        if self.touch_id {
            #[cfg(target_os = "macos")]
            {
                let service = self.effective_service();
                let account = self.build_key_name(key);
                let reason = format!("Update protected Fnox Keychain secret '{account}'");
                let service_c = std::ffi::CString::new(service.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Service names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let account_c = std::ffi::CString::new(account.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let reason_c =
                    std::ffi::CString::new(reason).map_err(|e| FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key name cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    })?;
                let value_bytes = value.as_bytes().to_vec();
                let result = spawn_keychain_blocking(move || {
                    touch_id::set(&service_c, &account_c, &value_bytes, &reason_c)
                })
                .await?;
                return result.map_err(|(status, details)| FnoxError::ProviderApiError {
                    provider: "Keychain".to_string(),
                    details: format!("Touch ID Keychain write failed (status {status}): {details}"),
                    hint: touch_id_error_hint(status).to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                });
            }
        }
        let entry = self.create_entry(key)?;
        let full_key = self.build_key_name(key);
        let service = self.service.clone();

        tracing::debug!(
            "Storing secret '{}' in OS keychain (service: '{}', key: '{}')",
            full_key,
            self.service,
            full_key
        );

        let value = value.to_string();
        let set_full_key = full_key.clone();
        let set_service = service.clone();
        spawn_keychain_blocking(move || entry.set_password(&value))
            .await?
            .map_err(|e| FnoxError::ProviderApiError {
                provider: "Keychain".to_string(),
                details: format!(
                    "Failed to store secret '{}' (service: '{}'): {}",
                    set_full_key, set_service, e
                ),
                hint: "Check that the keychain is accessible and writable".to_string(),
                url: "https://fnox.jdx.dev/providers/keychain".to_string(),
            })?;

        tracing::debug!(
            "Successfully stored secret '{}' in OS keychain (service: '{}')",
            full_key,
            self.service
        );
        Ok(())
    }
}

#[async_trait]
impl crate::providers::Provider for KeychainProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        if self.touch_id {
            #[cfg(target_os = "macos")]
            {
                let service = self.effective_service();
                let account = self.build_key_name(value);
                let reason = format!("access the protected Fnox secret '{account}'");
                let service_c = std::ffi::CString::new(service.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Service names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let account_c = std::ffi::CString::new(account.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let reason_c =
                    std::ffi::CString::new(reason).map_err(|e| FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key name cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    })?;
                let executable_c = std::ffi::CString::new(
                    env::current_exe()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "fnox".to_string()),
                )
                .expect("executable path cannot contain NUL bytes");
                let project_c = std::ffi::CString::new(
                    env::current_dir()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
                .expect("current directory cannot contain NUL bytes");
                let command_c = invoking_command_cstring();
                let result = spawn_keychain_blocking(move || {
                    touch_id::get(
                        &service_c,
                        &account_c,
                        &reason_c,
                        &executable_c,
                        &project_c,
                        &command_c,
                    )
                })
                .await?;
                return result.map_err(|(status, details)| {
                    if status == -25300 {
                        FnoxError::ProviderSecretNotFound {
                            provider: "Keychain (Touch ID)".to_string(),
                            secret: account,
                            hint: format!("Check that the secret exists in the protected Keychain service '{service}'"),
                            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                        }
                    } else {
                        FnoxError::ProviderAuthFailed {
                            provider: "Keychain (Touch ID)".to_string(),
                            details: format!("Touch ID Keychain read failed (status {status}): {details}"),
                            hint: touch_id_error_hint(status).to_string(),
                            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                        }
                    }
                });
            }
        }
        let entry = self.create_entry(value)?;
        let full_key = self.build_key_name(value);
        let service = self.service.clone();

        tracing::debug!(
            "Getting secret '{}' from OS keychain (service: '{}')",
            full_key,
            service
        );

        spawn_keychain_blocking(move || entry.get_password())
            .await?
            .map_err(|e| match e {
                keyring_core::Error::NoEntry => FnoxError::ProviderSecretNotFound {
                    provider: "Keychain".to_string(),
                    secret: full_key.clone(),
                    hint: format!(
                        "Check that the secret exists in the keychain (service: '{}')",
                        service
                    ),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                },
                keyring_core::Error::NoStorageAccess(_) => FnoxError::ProviderAuthFailed {
                    provider: "Keychain".to_string(),
                    details: e.to_string(),
                    hint: "Check that the keychain is unlocked and accessible".to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                },
                _ => FnoxError::ProviderApiError {
                    provider: "Keychain".to_string(),
                    details: e.to_string(),
                    hint: format!(
                        "Failed to get secret from keychain (service: '{}')",
                        service
                    ),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                },
            })
    }

    /// Override the default parallel `get_secrets_batch` to fetch keychain
    /// entries sequentially.
    ///
    /// The OS keychain API is synchronous and can pop a confirmation dialog
    /// per access. Running them concurrently would surface several
    /// overlapping dialogs and — once the number of secrets reaches the
    /// tokio worker-thread count — would also deadlock the runtime even with
    /// `spawn_blocking`, since the runtime still needs at least one free
    /// thread to drive completions.
    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let mut results = HashMap::with_capacity(secrets.len());
        for (key, value) in secrets {
            results.insert(key.clone(), self.get_secret(value).await);
        }
        results
    }

    async fn test_connection(&self) -> Result<()> {
        if self.touch_id {
            #[cfg(target_os = "macos")]
            {
                let test_account = format!("__fnox_touch_id_test_{:032x}", rand::random::<u128>());
                let service = format!("{}.test", self.effective_service());
                let service_c = std::ffi::CString::new(service.clone()).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Service names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let account_c = std::ffi::CString::new(test_account).map_err(|e| {
                    FnoxError::ProviderApiError {
                        provider: "Keychain".to_string(),
                        details: e.to_string(),
                        hint: "Key names cannot contain NUL bytes".to_string(),
                        url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                    }
                })?;
                let reason_c =
                    std::ffi::CString::new("validate Touch ID protected Keychain access")
                        .expect("static Touch ID reason contains no NUL bytes");
                let write_result = spawn_keychain_blocking({
                    let service_c = service_c.clone();
                    let account_c = account_c.clone();
                    let reason_c = reason_c.clone();
                    move || touch_id::set(&service_c, &account_c, b"fnox-touch-id-test", &reason_c)
                })
                .await?;
                write_result.map_err(|(status, details)| FnoxError::ProviderAuthFailed {
                    provider: "Keychain (Touch ID)".to_string(),
                    details: format!(
                        "Protected Keychain write failed (status {status}): {details}"
                    ),
                    hint: touch_id_error_hint(status).to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                })?;

                let executable_c = std::ffi::CString::new(
                    env::current_exe()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "fnox".to_string()),
                )
                .expect("executable path cannot contain NUL bytes");
                let project_c = std::ffi::CString::new(
                    env::current_dir()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
                .expect("project path cannot contain NUL bytes");
                let command_c = invoking_command_cstring();
                let read_result = spawn_keychain_blocking({
                    let service_c = service_c.clone();
                    let account_c = account_c.clone();
                    let reason_c = reason_c.clone();
                    move || {
                        touch_id::get(
                            &service_c,
                            &account_c,
                            &reason_c,
                            &executable_c,
                            &project_c,
                            &command_c,
                        )
                    }
                })
                .await?;
                let cleanup_result =
                    spawn_keychain_blocking(move || touch_id::delete(&service_c, &account_c))
                        .await?;
                read_result.map_err(|(status, details)| FnoxError::ProviderAuthFailed {
                    provider: "Keychain (Touch ID)".to_string(),
                    details: format!("Protected Keychain read failed (status {status}): {details}"),
                    hint: "Approve the Fnox Touch ID request and retry".to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                })?;
                cleanup_result.map_err(|(status, details)| FnoxError::ProviderApiError {
                    provider: "Keychain (Touch ID)".to_string(),
                    details: format!("Unable to remove the temporary validation entry (status {status}): {details}"),
                    hint: "Remove the temporary Fnox Touch ID validation item from Keychain Access"
                        .to_string(),
                    url: "https://fnox.jdx.dev/providers/keychain".to_string(),
                })?;
                return Ok(());
            }
        }
        // Try to create an entry with a test key to verify keychain access
        let test_key = "__fnox_test__";
        let entry = self.create_entry(test_key)?;
        let service = self.service.clone();

        // Run all three blocking operations on a single background thread to
        // avoid hopping through the runtime three times.
        spawn_keychain_blocking(move || {
            entry.set_password("test")?;
            entry.get_password()?;
            let _ = entry.delete_credential();
            Ok(())
        })
        .await?
        .map_err(|e: keyring_core::Error| FnoxError::ProviderAuthFailed {
            provider: "Keychain".to_string(),
            details: format!("Failed to access keychain (service: '{service}'): {e}"),
            hint: "Check that you have permission to access the OS keychain".to_string(),
            url: "https://fnox.jdx.dev/providers/keychain".to_string(),
        })
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        self.put_secret(key, value).await?;
        // Return the key name to store in config
        Ok(key.to_string())
    }
}

/// Run a blocking keyring call on tokio's blocking thread pool.
///
/// The OS keychain APIs are synchronous and may present a system dialog that
/// blocks until the user responds. Calling them directly on a tokio worker
/// thread pins that thread — concurrent calls can deadlock the runtime.
async fn spawn_keychain_blocking<F, T>(f: F) -> Result<T>
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

fn platform_backend_hint() -> &'static str {
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
fn invoking_command_cstring() -> std::ffi::CString {
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
fn touch_id_error_hint(status: i32) -> &'static str {
    if status == -34018 {
        "This build lacks an Apple-authorized Keychain access group. Touch ID requires a macOS app bundle signed with a matching Developer ID provisioning profile and keychain-access-groups entitlement."
    } else {
        "Check that Touch ID is enrolled and approve the Fnox Keychain request"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;

    #[tokio::test]
    async fn test_keychain_set_and_get() {
        let provider = KeychainProvider::new("fnox-unit-test".to_string(), None, false).unwrap();

        if let Err(err) = provider.test_connection().await {
            if is_keychain_unavailable(&err) {
                eprintln!("skipping keychain test: {err}");
                return;
            }
            panic!("Failed to connect to keychain: {err:?}");
        }

        // Set a secret
        let result = provider.put_secret("test_key", "test_value").await;
        assert!(result.is_ok(), "Failed to set secret: {:?}", result.err());

        // Get it back
        let result = provider.get_secret("test_key").await;
        assert!(result.is_ok(), "Failed to get secret: {:?}", result.err());
        assert_eq!(result.unwrap(), "test_value");

        // Clean up
        let entry = provider.create_entry("test_key").unwrap();
        let _ = entry.delete_credential();
    }

    fn is_keychain_unavailable(err: &FnoxError) -> bool {
        matches!(err, FnoxError::ProviderAuthFailed { .. })
    }
}

#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn read_touch_id_for_helper(
    service: &str,
    account: &str,
    reason: &str,
    executable: &str,
    project: &str,
    command: &str,
) -> std::result::Result<String, (i32, String)> {
    let to_c_string =
        |value: &str| std::ffi::CString::new(value).map_err(|error| (-50, error.to_string()));
    touch_id::get_on_main_thread(
        &to_c_string(service)?,
        &to_c_string(account)?,
        &to_c_string(reason)?,
        &to_c_string(executable)?,
        &to_c_string(project)?,
        &to_c_string(command)?,
    )
}

#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn write_touch_id_for_helper(
    service: &str,
    account: &str,
    value: &[u8],
    reason: &str,
) -> std::result::Result<(), (i32, String)> {
    let to_c_string =
        |value: &str| std::ffi::CString::new(value).map_err(|error| (-50, error.to_string()));
    touch_id::set_on_current_process(
        &to_c_string(service)?,
        &to_c_string(account)?,
        value,
        &to_c_string(reason)?,
    )
}

#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn delete_touch_id_for_helper(
    service: &str,
    account: &str,
) -> std::result::Result<(), (i32, String)> {
    if !is_touch_id_test_item(service, account) {
        return Err((
            -50,
            "Refusing to delete outside the temporary Touch ID test namespace".to_string(),
        ));
    }
    let to_c_string =
        |value: &str| std::ffi::CString::new(value).map_err(|error| (-50, error.to_string()));
    touch_id::delete_on_current_process(&to_c_string(service)?, &to_c_string(account)?)
}

#[cfg(target_os = "macos")]
fn is_touch_id_test_item(service: &str, account: &str) -> bool {
    service.ends_with(".touch-id.test")
        && account
            .strip_prefix("__fnox_touch_id_test_")
            .is_some_and(|suffix| {
                suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
}

#[cfg(all(test, target_os = "macos"))]
mod touch_id_cleanup_tests {
    use super::is_touch_id_test_item;

    #[test]
    fn cleanup_accepts_only_random_validation_items_in_the_test_service() {
        assert!(is_touch_id_test_item(
            "fnox.touch-id.test",
            "__fnox_touch_id_test_0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_touch_id_test_item(
            "fnox.touch-id",
            "__fnox_touch_id_test_0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_touch_id_test_item(
            "fnox.touch-id.test",
            "production-secret"
        ));
        assert!(!is_touch_id_test_item(
            "fnox.touch-id.test",
            "__fnox_touch_id_test_short"
        ));
    }
}

#[cfg(target_os = "macos")]
mod touch_id {
    use crate::env;
    use std::ffi::{CStr, CString, c_char, c_void};

    unsafe extern "C" {
        fn fnox_touch_id_validate_helper(path: *const c_char, error_out: *mut *mut c_char) -> i32;
        fn fnox_touch_id_get(
            service: *const c_char,
            account: *const c_char,
            reason: *const c_char,
            executable: *const c_char,
            project: *const c_char,
            command: *const c_char,
            value_out: *mut *mut c_char,
            length_out: *mut usize,
            error_out: *mut *mut c_char,
        ) -> i32;
        fn fnox_touch_id_set(
            service: *const c_char,
            account: *const c_char,
            value: *const u8,
            value_length: usize,
            reason: *const c_char,
            error_out: *mut *mut c_char,
        ) -> i32;
        fn fnox_touch_id_delete(
            service: *const c_char,
            account: *const c_char,
            error_out: *mut *mut c_char,
        ) -> i32;
        fn fnox_touch_id_free(pointer: *mut c_void);
    }

    fn copy_error(pointer: *mut c_char) -> String {
        if pointer.is_null() {
            return "No operating system details were provided".to_string();
        }
        // SAFETY: the native shim returns an owned NUL-terminated string.
        let message = unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: the pointer came from fnox_copy_error in the native shim.
        unsafe { fnox_touch_id_free(pointer.cast()) };
        message
    }

    pub(super) fn get(
        service: &CString,
        account: &CString,
        reason: &CString,
        executable: &CString,
        project: &CString,
        command: &CString,
    ) -> std::result::Result<String, (i32, String)> {
        let output = run_touch_id_helper(
            &[
                "__touch-id-read",
                service.to_str().unwrap_or_default(),
                account.to_str().unwrap_or_default(),
                reason.to_str().unwrap_or_default(),
                executable.to_str().unwrap_or_default(),
                project.to_str().unwrap_or_default(),
                command.to_str().unwrap_or_default(),
            ],
            None,
        )?;
        String::from_utf8(output).map_err(|error| (-1, error.to_string()))
    }

    pub(super) fn get_on_main_thread(
        service: &CString,
        account: &CString,
        reason: &CString,
        executable: &CString,
        project: &CString,
        command: &CString,
    ) -> std::result::Result<String, (i32, String)> {
        let mut value = std::ptr::null_mut();
        let mut length = 0;
        let mut error = std::ptr::null_mut();
        // SAFETY: all C strings stay alive for the synchronous call; output pointers
        // are initialized here and owned buffers are released below.
        let status = unsafe {
            fnox_touch_id_get(
                service.as_ptr(),
                account.as_ptr(),
                reason.as_ptr(),
                executable.as_ptr(),
                project.as_ptr(),
                command.as_ptr(),
                &mut value,
                &mut length,
                &mut error,
            )
        };
        if status != 0 {
            return Err((status, copy_error(error)));
        }
        if value.is_null() {
            return Err((
                status,
                "Keychain returned an empty result pointer".to_string(),
            ));
        }
        // SAFETY: native shim allocated `length` bytes for this result.
        let bytes = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), length) }.to_vec();
        // SAFETY: the pointer came from the native shim.
        unsafe { fnox_touch_id_free(value.cast()) };
        String::from_utf8(bytes).map_err(|error| (-1, error.to_string()))
    }

    pub(super) fn set(
        service: &CString,
        account: &CString,
        value: &[u8],
        reason: &CString,
    ) -> std::result::Result<(), (i32, String)> {
        if !current_executable_is_in_app_bundle() {
            run_touch_id_helper(
                &[
                    "__touch-id-set",
                    service.to_str().unwrap_or_default(),
                    account.to_str().unwrap_or_default(),
                    reason.to_str().unwrap_or_default(),
                ],
                Some(value),
            )?;
            return Ok(());
        }
        set_on_current_process(service, account, value, reason)
    }

    pub(super) fn set_on_current_process(
        service: &CString,
        account: &CString,
        value: &[u8],
        reason: &CString,
    ) -> std::result::Result<(), (i32, String)> {
        let mut error = std::ptr::null_mut();
        // SAFETY: pointers remain valid for the synchronous call; value is passed
        // with its explicit length and is never interpreted as a C string.
        let status = unsafe {
            fnox_touch_id_set(
                service.as_ptr(),
                account.as_ptr(),
                value.as_ptr(),
                value.len(),
                reason.as_ptr(),
                &mut error,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err((status, copy_error(error)))
        }
    }

    pub(super) fn delete(
        service: &CString,
        account: &CString,
    ) -> std::result::Result<(), (i32, String)> {
        if !super::is_touch_id_test_item(
            service.to_str().unwrap_or_default(),
            account.to_str().unwrap_or_default(),
        ) {
            return Err((
                -50,
                "Refusing to delete outside the temporary Touch ID test namespace".to_string(),
            ));
        }
        if !current_executable_is_in_app_bundle() {
            run_touch_id_helper(
                &[
                    "__touch-id-delete",
                    service.to_str().unwrap_or_default(),
                    account.to_str().unwrap_or_default(),
                ],
                None,
            )?;
            return Ok(());
        }
        delete_on_current_process(service, account)
    }

    pub(super) fn delete_on_current_process(
        service: &CString,
        account: &CString,
    ) -> std::result::Result<(), (i32, String)> {
        let mut error = std::ptr::null_mut();
        // SAFETY: pointers remain valid for the synchronous delete call.
        let status =
            unsafe { fnox_touch_id_delete(service.as_ptr(), account.as_ptr(), &mut error) };
        if status == 0 {
            Ok(())
        } else {
            Err((status, copy_error(error)))
        }
    }

    fn current_executable_is_in_app_bundle() -> bool {
        let Ok(executable) = env::current_exe() else {
            return false;
        };
        executable
            .parent()
            .and_then(std::path::Path::parent)
            .and_then(std::path::Path::parent)
            .is_some_and(|bundle| bundle.extension().is_some_and(|ext| ext == "app"))
    }

    fn touch_id_helper_executable() -> std::result::Result<std::path::PathBuf, (i32, String)> {
        let current = env::current_exe()
            .map_err(|error| (-1, format!("Unable to locate Fnox executable: {error}")))?;
        let helper = if current_executable_is_in_app_bundle() {
            current
        } else {
            let helper_relative = std::path::Path::new("Fnox.app/Contents/MacOS/fnox");
            let mut candidates = Vec::new();
            if let Some(directory) = current.parent() {
                candidates.push(directory.join(helper_relative));
                candidates.push(directory.join("../").join(helper_relative));
            }
            candidates.push(std::path::PathBuf::from(
                "/Applications/Fnox.app/Contents/MacOS/fnox",
            ));
            if let Some(home) = env::var_os("HOME") {
                candidates.push(
                    std::path::PathBuf::from(home)
                        .join("Applications/Fnox.app/Contents/MacOS/fnox"),
                );
            }
            candidates
                .into_iter()
                .find(|candidate| candidate.is_file())
                .ok_or_else(|| {
            (
                -34018,
                "A provisioned Fnox.app helper was not found. Install Fnox.app beside the CLI or in /Applications; biometric Keychain access requires its signed app bundle.".to_string(),
            )
                })?
        };
        validate_helper_signature(&helper)?;
        Ok(helper)
    }

    fn validate_helper_signature(path: &std::path::Path) -> std::result::Result<(), (i32, String)> {
        let path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|error| (-50, error.to_string()))?;
        let mut error = std::ptr::null_mut();
        // SAFETY: path is NUL-terminated and error is an initialized output pointer.
        let status = unsafe { fnox_touch_id_validate_helper(path.as_ptr(), &mut error) };
        if status == 0 {
            Ok(())
        } else {
            Err((status, copy_error(error)))
        }
    }

    fn run_touch_id_helper(
        args: &[&str],
        input: Option<&[u8]>,
    ) -> std::result::Result<Vec<u8>, (i32, String)> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let executable = touch_id_helper_executable()?;
        let mut command = Command::new(executable);
        command.args(args);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command.stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = command
            .spawn()
            .map_err(|error| (-1, format!("Unable to start Fnox Touch ID helper: {error}")))?;
        if let Some(input) = input {
            child
                .stdin
                .take()
                .expect("Touch ID helper stdin was piped")
                .write_all(input)
                .map_err(|error| {
                    (
                        -1,
                        format!("Unable to send secret to Fnox Touch ID helper: {error}"),
                    )
                })?;
        }
        let output = child.wait_with_output().map_err(|error| {
            (
                -1,
                format!("Unable to read Fnox Touch ID helper result: {error}"),
            )
        })?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let (status, details) = stderr.split_once('\n').unwrap_or(("-1", &stderr));
        Err((
            status.trim().parse().unwrap_or(-1),
            details.trim().to_string(),
        ))
    }
}
