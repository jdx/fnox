#[cfg(target_os = "macos")]
#[doc(hidden)]
pub const TOUCH_ID_HELPER_APPROVAL: u8 = 0xA5;

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
    native::get_on_main_thread(
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
pub fn validate_touch_id_helper_parent() -> std::result::Result<(), (i32, String)> {
    native::validate_parent_process()
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
    native::set_on_current_process(
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
    native::delete_on_current_process(&to_c_string(service)?, &to_c_string(account)?)
}

#[cfg(target_os = "macos")]
pub(super) use native::{delete, get, set};

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
pub(super) mod native {
    use crate::env;
    use std::ffi::{CStr, CString, c_char, c_void};

    unsafe extern "C" {
        fn fnox_touch_id_validate_helper(path: *const c_char, error_out: *mut *mut c_char) -> i32;
        fn fnox_touch_id_validate_pid(pid: i32, error_out: *mut *mut c_char) -> i32;
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

    pub(in crate::providers::keychain) fn get(
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

    pub(super) fn validate_parent_process() -> std::result::Result<(), (i32, String)> {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            fnox_touch_id_validate_pid(std::os::unix::process::parent_id() as i32, &mut error)
        };
        if status == 0 {
            Ok(())
        } else {
            Err((status, copy_error(error)))
        }
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

    pub(in crate::providers::keychain) fn set(
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
        let executable = env::current_exe().map_err(|error| (-1, error.to_string()))?;
        validate_helper_signature(&executable)?;
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

    pub(in crate::providers::keychain) fn delete(
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
            let mut errors = Vec::new();
            let mut selected = None;
            for candidate in candidates
                .into_iter()
                .filter(|candidate| candidate.is_file())
            {
                match validate_helper_signature(&candidate) {
                    Ok(()) => {
                        selected = Some(candidate);
                        break;
                    }
                    Err((_, error)) => errors.push(format!("{}: {error}", candidate.display())),
                }
            }
            selected.ok_or_else(|| {
                if !errors.is_empty() {
                    return (-34018, format!("No provisioned Fnox.app helper passed signature validation: {}", errors.join("; ")));
                }
            (
                -34018,
                "A provisioned Fnox.app helper was not found. Install Fnox.app beside the CLI or in /Applications; biometric Keychain access requires its signed app bundle.".to_string(),
            )
                })?
        };
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
        validate_helper_signature(&executable)?;
        let mut command = Command::new(executable);
        command.args(args);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command.stdin(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| (-1, format!("Unable to start Fnox Touch ID helper: {error}")))?;
        let mut identity_error = std::ptr::null_mut();
        // Verify the actual launched process after spawn and before sending it
        // any secret bytes, closing the path replacement window.
        let status = unsafe { fnox_touch_id_validate_pid(child.id() as i32, &mut identity_error) };
        if status != 0 {
            let details = copy_error(identity_error);
            let _ = child.kill();
            let _ = child.wait();
            return Err((status, details));
        }
        let mut stdin = child.stdin.take().expect("Touch ID helper stdin was piped");
        if let Err(error) = stdin.write_all(&[super::TOUCH_ID_HELPER_APPROVAL]) {
            let _ = child.kill();
            let _ = child.wait();
            return Err((
                -1,
                format!("Unable to approve Fnox Touch ID helper: {error}"),
            ));
        }
        if let Some(input) = input {
            let write_result = stdin.write_all(input);
            if let Err(error) = write_result {
                let _ = child.kill();
                let _ = child.wait();
                return Err((
                    -1,
                    format!("Unable to send secret to Fnox Touch ID helper: {error}"),
                ));
            }
        }
        drop(stdin);
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
