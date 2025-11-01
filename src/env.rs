pub use std::env::*;
use std::{path::PathBuf, sync::LazyLock};

// Directory configuration
pub static HOME_DIR: LazyLock<PathBuf> = LazyLock::new(|| dirs::home_dir().unwrap_or_default());
pub static FNOX_CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    var_path("FNOX_CONFIG_DIR").unwrap_or_else(|| {
        #[cfg(unix)]
        let default = HOME_DIR.join(".config").join("fnox");
        #[cfg(windows)]
        let default = HOME_DIR.join("AppData").join("Local").join("fnox");
        default
    })
});

// Profile configuration
pub static FNOX_PROFILE: LazyLock<Option<String>> = LazyLock::new(|| {
    var("FNOX_PROFILE").ok().and_then(|profile| {
        if is_valid_profile_name(&profile) {
            Some(profile)
        } else {
            eprintln!("Warning: Invalid FNOX_PROFILE value '{}' ignored (contains path separators or invalid characters)", profile);
            None
        }
    })
});

// Age encryption key configuration
pub static FNOX_AGE_KEY: LazyLock<Option<String>> = LazyLock::new(|| var("FNOX_AGE_KEY").ok());

// Helper functions for parsing environment variables
fn var_path(name: &str) -> Option<PathBuf> {
    var(name).map(PathBuf::from).ok()
}

/// Validates that a profile name is safe to use in file paths
/// Rejects names containing path separators or other dangerous characters
fn is_valid_profile_name(name: &str) -> bool {
    // Profile names must be non-empty
    if name.is_empty() {
        return false;
    }

    // Reject path separators and other dangerous characters
    // Allow: alphanumeric, dash, underscore, dot (but not .. or .)
    if name == "." || name == ".." {
        return false;
    }

    // Check for path separators or other dangerous characters
    for ch in name.chars() {
        match ch {
            // Path separators
            '/' | '\\' => return false,
            // Null byte (could truncate paths)
            '\0' => return false,
            // Control characters
            c if c.is_control() => return false,
            // Allow everything else (alphanumeric, dash, underscore, dot)
            _ => {}
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_var_path() {
        unsafe {
            set_var("FNOX_TEST_PATH", "/foo/bar");
            assert_eq!(
                var_path("FNOX_TEST_PATH").unwrap(),
                PathBuf::from("/foo/bar")
            );
            remove_var("FNOX_TEST_PATH");
        }
    }

    #[test]
    fn test_valid_profile_names() {
        // Valid profile names
        assert!(is_valid_profile_name("production"));
        assert!(is_valid_profile_name("staging"));
        assert!(is_valid_profile_name("dev"));
        assert!(is_valid_profile_name("test-env"));
        assert!(is_valid_profile_name("test_env"));
        assert!(is_valid_profile_name("prod-v2.0"));
        assert!(is_valid_profile_name("env123"));
    }

    #[test]
    fn test_invalid_profile_names() {
        // Path traversal attempts
        assert!(!is_valid_profile_name("../../../etc/passwd"));
        assert!(!is_valid_profile_name(".."));
        assert!(!is_valid_profile_name("."));
        assert!(!is_valid_profile_name("../production"));
        assert!(!is_valid_profile_name("production/../../etc/passwd"));

        // Absolute paths
        assert!(!is_valid_profile_name("/etc/passwd"));
        assert!(!is_valid_profile_name("/tmp/evil"));

        // Windows paths
        assert!(!is_valid_profile_name("C:\\Windows\\System32"));
        assert!(!is_valid_profile_name("..\\..\\evil"));

        // Empty and special characters
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name("prod\0uction")); // null byte
        assert!(!is_valid_profile_name("prod\ntest")); // newline
        assert!(!is_valid_profile_name("prod\rtest")); // carriage return
    }
}
