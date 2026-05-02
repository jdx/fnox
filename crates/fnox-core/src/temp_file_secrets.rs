use crate::error::{FnoxError, Result};
use std::env;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

/// Create an ephemeral temporary file with the secret value and restricted permissions.
///
/// The returned [`NamedTempFile`] deletes itself when dropped.
pub fn create_ephemeral_secret_file(key: &str, value: &str) -> Result<NamedTempFile> {
    // Create a named temporary file
    let mut temp_file = NamedTempFile::new().map_err(|e| {
        FnoxError::Config(format!(
            "Failed to create temporary file for secret '{}': {}",
            key, e
        ))
    })?;

    // Set restrictive permissions (0600 - read/write for owner only) on Unix.
    #[cfg(unix)]
    {
        let metadata = temp_file.as_file().metadata().map_err(|e| {
            FnoxError::Config(format!(
                "Failed to get metadata for temporary file of secret '{}': {}",
                key, e
            ))
        })?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(temp_file.path(), permissions).map_err(|e| {
            FnoxError::Config(format!(
                "Failed to set permissions for temporary file of secret '{}': {}",
                key, e
            ))
        })?;
    }

    // Write the secret value to the file
    temp_file.write_all(value.as_bytes()).map_err(|e| {
        FnoxError::Config(format!(
            "Failed to write secret '{}' to temporary file: {}",
            key, e
        ))
    })?;

    // Flush to ensure the data is written
    temp_file.flush().map_err(|e| {
        FnoxError::Config(format!(
            "Failed to flush temporary file for secret '{}': {}",
            key, e
        ))
    })?;

    Ok(temp_file)
}

/// Create a persistent temporary file with the secret value and restricted permissions.
///
/// The `prefix` is used to distinguish caller contexts (e.g., `\"fnox-\"`, `\"fnox-export-\"`,
/// `\"fnox-hook-\"`). Returns the file path as a `String`.
pub fn create_persistent_secret_file(prefix: &str, key: &str, value: &str) -> Result<String> {
    // Create a unique filename in the system temp directory
    let temp_dir = env::temp_dir();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            FnoxError::Config(format!(
                "Failed to get system time for secret '{}': {}",
                key, e
            ))
        })?
        .as_nanos();
    let pid = std::process::id();
    let filename = format!("{}{}-{}-{}", prefix, key, pid, timestamp);
    let file_path = temp_dir.join(filename);

    // Create and write to the file
    let mut file = fs::File::create(&file_path).map_err(|e| {
        FnoxError::Config(format!(
            "Failed to create persistent file for secret '{}': {}",
            key, e
        ))
    })?;

    // Set restrictive permissions (0600 - read/write for owner only) on Unix.
    #[cfg(unix)]
    {
        let metadata = file.metadata().map_err(|e| {
            FnoxError::Config(format!(
                "Failed to get metadata for persistent file of secret '{}': {}",
                key, e
            ))
        })?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&file_path, permissions).map_err(|e| {
            FnoxError::Config(format!(
                "Failed to set permissions for persistent file of secret '{}': {}",
                key, e
            ))
        })?;
    }

    file.write_all(value.as_bytes()).map_err(|e| {
        FnoxError::Config(format!(
            "Failed to write secret '{}' to persistent file: {}",
            key, e
        ))
    })?;

    file.flush().map_err(|e| {
        FnoxError::Config(format!(
            "Failed to flush persistent file for secret '{}': {}",
            key, e
        ))
    })?;

    Ok(file_path.to_string_lossy().to_string())
}
