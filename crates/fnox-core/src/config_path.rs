use std::path::{Path, PathBuf};

/// Expands `~` in a config path using the current user's home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(path).to_string())
}

/// Resolve a path declared in config against the directory containing that config file.
///
/// Absolute paths are returned unchanged. Paths starting with `~` are expanded
/// before relative resolution, so they also become absolute. When no source
/// file is available, relative paths are preserved.
pub fn resolve_relative_to_file(path: &str, source_file: Option<&Path>) -> PathBuf {
    let expanded = expand_tilde(path);
    if expanded.is_absolute() {
        return expanded;
    }

    source_file
        .and_then(Path::parent)
        .map(|parent| parent.join(&expanded))
        .unwrap_or(expanded)
}

/// Resolve a path declared in config against an already-known config directory.
pub fn resolve_relative_to_dir(path: &str, source_dir: Option<&Path>) -> PathBuf {
    let expanded = expand_tilde(path);
    if expanded.is_absolute() {
        return expanded;
    }

    source_dir
        .map(|dir| dir.join(&expanded))
        .unwrap_or(expanded)
}

/// Resolve a string path and return a string, preserving the original string if
/// the resolved path cannot be represented as UTF-8.
pub fn resolve_string_relative_to_file(path: String, source_file: Option<&Path>) -> String {
    resolve_relative_to_file(&path, source_file)
        .into_os_string()
        .into_string()
        .unwrap_or(path)
}

pub fn resolve_optional_string_relative_to_file(
    path: Option<String>,
    source_file: Option<&Path>,
) -> Option<String> {
    path.map(|path| resolve_string_relative_to_file(path, source_file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_path_against_source_file_parent() {
        assert_eq!(
            resolve_relative_to_file(
                "./secrets/vault.kdbx",
                Some(Path::new("/home/user/project/fnox.toml")),
            ),
            PathBuf::from("/home/user/project/./secrets/vault.kdbx"),
        );
    }

    #[test]
    fn resolves_relative_path_against_source_dir() {
        assert_eq!(
            resolve_relative_to_dir("./shared.toml", Some(Path::new("/home/user/project"))),
            PathBuf::from("/home/user/project/./shared.toml"),
        );
    }

    #[test]
    fn leaves_absolute_path_unchanged() {
        assert_eq!(
            resolve_relative_to_file(
                "/var/lib/password-store",
                Some(Path::new("/home/user/project/fnox.toml")),
            ),
            PathBuf::from("/var/lib/password-store"),
        );
    }

    #[test]
    fn preserves_relative_path_without_source() {
        assert_eq!(
            resolve_relative_to_file("./password-store", None),
            PathBuf::from("./password-store"),
        );
    }
}
