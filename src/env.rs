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
pub static FNOX_PROFILE: LazyLock<Option<String>> = LazyLock::new(|| var("FNOX_PROFILE").ok());

// Age encryption key configuration
pub static FNOX_AGE_KEY: LazyLock<Option<String>> = LazyLock::new(|| var("FNOX_AGE_KEY").ok());

// Helper functions for parsing environment variables
fn var_path(name: &str) -> Option<PathBuf> {
    var(name).map(PathBuf::from).ok()
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
}
