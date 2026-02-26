//! Global registry of config file sources for error reporting with miette.
//!
//! This module maintains a cache of config file contents so that when errors
//! occur, we can display the relevant source code with span highlighting.

use miette::NamedSource;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};

/// Global registry mapping canonical paths to their source content.
static SOURCES: LazyLock<RwLock<HashMap<PathBuf, Arc<String>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Register a config file's source content for later error reporting.
///
/// The path is canonicalized to ensure consistent lookups regardless of
/// how the path was originally specified.
pub fn register(path: &Path, content: String) {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if let Ok(mut sources) = SOURCES.write() {
        sources.insert(canonical, Arc::new(content));
    }
}

/// Get a NamedSource for the given path, suitable for use with miette errors.
///
/// Returns None if the path was never registered or if the lock cannot be acquired.
/// Returns Arc<NamedSource<...>> to keep the error type size small (Arc is pointer-sized).
pub fn get_named_source(path: &Path) -> Option<Arc<NamedSource<Arc<String>>>> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let sources = SOURCES.read().ok()?;
    sources.get(&canonical).map(|content| {
        Arc::new(NamedSource::new(
            path.display().to_string(),
            Arc::clone(content),
        ))
    })
}

/// Get the raw source content for a path.
///
/// Useful when you need the content without wrapping it in NamedSource.
#[cfg(test)]
pub fn get_content(path: &Path) -> Option<Arc<String>> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let sources = SOURCES.read().ok()?;
    sources.get(&canonical).cloned()
}

/// Clear all registered sources. Primarily useful for testing.
#[cfg(test)]
pub fn clear() {
    if let Ok(mut sources) = SOURCES.write() {
        sources.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_register_and_get() {
        clear();

        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, "test content").unwrap();
        let path = temp.path();

        register(path, "test content\n".to_string());

        let source = get_named_source(path);
        assert!(source.is_some());

        let content = get_content(path);
        assert_eq!(content.as_deref(), Some(&"test content\n".to_string()));
    }

    #[test]
    fn test_missing_path() {
        clear();

        let path = Path::new("/nonexistent/path/to/file.toml");
        assert!(get_named_source(path).is_none());
        assert!(get_content(path).is_none());
    }
}
