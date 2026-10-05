//! Profile names, normalized the way the fnox CLI does.

/// Normalize a profile list: split comma-separated entries, trim whitespace,
/// drop invalid names, and remove empty entries. Order is preserved. An empty
/// result becomes `["default"]`.
pub fn normalize(input: &[String]) -> Vec<String> {
    let profiles: Vec<String> = input
        .iter()
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && is_valid_name(s))
        .collect();
    if profiles.is_empty() {
        vec!["default".to_string()]
    } else {
        profiles
    }
}

/// Validates that a profile name is safe to use in file paths.
/// Rejects names containing path separators or other dangerous characters.
pub fn is_valid_name(name: &str) -> bool {
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
            // Comma — used as delimiter in multi-profile lists (FNOX_PROFILE=a,b)
            // and in socket-path/cache-key joins. Allowing it would cause
            // collisions: "a,b" as one name vs "a" + "b" as two names.
            ',' => return false,
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
    fn test_valid_profile_names() {
        // Valid profile names
        assert!(is_valid_name("production"));
        assert!(is_valid_name("staging"));
        assert!(is_valid_name("dev"));
        assert!(is_valid_name("test-env"));
        assert!(is_valid_name("test_env"));
        assert!(is_valid_name("prod-v2.0"));
        assert!(is_valid_name("env123"));
    }

    #[test]
    fn test_invalid_profile_names() {
        // Path traversal attempts
        assert!(!is_valid_name("../../../etc/passwd"));
        assert!(!is_valid_name(".."));
        assert!(!is_valid_name("."));
        assert!(!is_valid_name("../production"));
        assert!(!is_valid_name("production/../../etc/passwd"));

        // Absolute paths
        assert!(!is_valid_name("/etc/passwd"));
        assert!(!is_valid_name("/tmp/evil"));

        // Windows paths
        assert!(!is_valid_name("C:\\Windows\\System32"));
        assert!(!is_valid_name("..\\..\\evil"));

        // Empty and special characters
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("prod\0uction")); // null byte
        assert!(!is_valid_name("prod\ntest")); // newline
        assert!(!is_valid_name("prod\rtest")); // carriage return

        // Comma — used as multi-profile delimiter, must be rejected
        // to prevent cache-key/socket-path collisions.
        assert!(!is_valid_name("a,b"));
        assert!(!is_valid_name("prod,"));
        assert!(!is_valid_name(",prod"));
    }

    #[test]
    fn normalize_splits_trims_drops_invalid_and_defaults() {
        let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(normalize(&s(&["dev, prod"])), s(&["dev", "prod"]));
        assert_eq!(normalize(&s(&["../bad", "ok"])), s(&["ok"]));
        assert_eq!(normalize(&s(&["../bad"])), s(&["default"]));
        assert_eq!(normalize(&s(&[])), s(&["default"]));
        assert_eq!(normalize(&s(&[""])), s(&["default"]));
    }
}
