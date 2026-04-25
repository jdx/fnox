use crate::config::{Config, all_config_filenames};
use crate::env;
use crate::error::Result;
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use crate::commands::Cli;

#[derive(serde::Deserialize)]
struct PartialConfig {
    #[serde(default)]
    root: bool,
    #[serde(default)]
    import: Vec<String>,
}

#[derive(clap::Args)]
pub struct ConfigFilesCommand;

impl ConfigFilesCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        let profile = crate::settings::Settings::get().profile.clone();
        let filenames = all_config_filenames(Some(&profile));

        let current_dir = env::current_dir().map_err(|e| {
            crate::error::FnoxError::Config(format!("Failed to get current directory: {}", e))
        })?;

        let mut printed = HashSet::new();
        self.collect_recursive(&current_dir, &filenames, &mut printed)?;

        // Global config is always checked
        let global = normalize_path(Config::global_config_path());
        if global.exists() && printed.insert(global.clone()) {
            println!("{}", global.display());
            if let Some(partial) = self.read_partial_config(&global) {
                let base_dir = global.parent().unwrap_or_else(|| Path::new("."));
                self.print_imports_from_partial(base_dir, &partial, &mut printed);
            }
        }

        Ok(())
    }

    fn collect_recursive(
        &self,
        dir: &Path,
        filenames: &[String],
        printed: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        let mut found_root = false;

        for filename in filenames {
            let path = normalize_path(dir.join(filename));
            if path.exists() && printed.insert(path.clone()) {
                println!("{}", path.display());

                if let Some(partial) = self.read_partial_config(&path) {
                    self.print_imports_from_partial(dir, &partial, printed);
                    if partial.root {
                        found_root = true;
                    }
                }
            }
        }

        if found_root {
            return Ok(());
        }

        if let Some(parent) = dir.parent() {
            self.collect_recursive(parent, filenames, printed)?;
        }

        Ok(())
    }

    fn read_partial_config(&self, path: &Path) -> Option<PartialConfig> {
        let content = std::fs::read_to_string(path).ok()?;
        toml_edit::de::from_str::<PartialConfig>(&content).ok()
    }

    fn print_imports_from_partial(
        &self,
        base_dir: &Path,
        partial: &PartialConfig,
        printed: &mut HashSet<PathBuf>,
    ) {
        for import_path in &partial.import {
            let import = if Path::new(import_path).is_absolute() {
                PathBuf::from(import_path)
            } else {
                base_dir.join(import_path)
            };
            if import.exists() {
                let normalized = normalize_path(import);
                if printed.insert(normalized.clone()) {
                    println!("{}", normalized.display());
                }
            }
        }
    }
}

/// Lexically normalize a path: collapse `.` and `..` segments without touching
/// the filesystem or resolving symlinks.
fn normalize_path(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                let can_pop = matches!(out.components().next_back(), Some(Component::Normal(_)));
                if can_pop {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_path;
    use std::path::PathBuf;

    #[test]
    fn collapses_cur_dir() {
        assert_eq!(
            normalize_path(PathBuf::from("/a/./b/./c")),
            PathBuf::from("/a/b/c")
        );
    }

    #[test]
    fn collapses_parent_dir() {
        assert_eq!(
            normalize_path(PathBuf::from("/a/b/../c")),
            PathBuf::from("/a/c")
        );
    }

    #[test]
    fn preserves_leading_parent_dir() {
        assert_eq!(
            normalize_path(PathBuf::from("../a/b")),
            PathBuf::from("../a/b")
        );
    }

    #[test]
    fn empty_becomes_cur_dir() {
        assert_eq!(normalize_path(PathBuf::from("a/..")), PathBuf::from("."));
    }

    #[test]
    fn relative_import_pattern() {
        assert_eq!(
            normalize_path(PathBuf::from("/home/user/.config/fnox/./providers.toml")),
            PathBuf::from("/home/user/.config/fnox/providers.toml")
        );
    }
}
