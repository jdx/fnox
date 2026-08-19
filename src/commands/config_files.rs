use crate::config::{Config, all_config_filenames, uses_config_discovery};
use crate::env;
use crate::error::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::commands::Cli;

#[derive(serde::Deserialize)]
struct PartialConfig {
    #[serde(default)]
    root: bool,
    #[serde(default)]
    import: Vec<String>,
}

#[derive(usage_derive::Args)]
pub struct ConfigFilesCommand {}

impl ConfigFilesCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        let profile = Config::get_profiles(&[]);
        let filenames = all_config_filenames(&profile);

        let current_dir = env::current_dir().map_err(|e| {
            crate::error::FnoxError::Config(format!("Failed to get current directory: {}", e))
        })?;

        let mut printed = HashSet::new();

        // An explicit --config path skips the upward search entirely, so
        // list only that file (plus its imports) and the global config.
        if uses_config_discovery(&cli.config) {
            self.collect_recursive(&current_dir, &filenames, &mut printed)?;
        } else {
            let explicit = if cli.config.is_relative() {
                current_dir.join(&cli.config)
            } else {
                cli.config.clone()
            };
            // A missing or unparseable explicit config — or import of one —
            // makes loading fail before the global layer is reached, so
            // surface the same errors rather than reporting a load order
            // that can't happen.
            let config = Config::load(&explicit)?;
            println!("{}", explicit.display());
            printed.insert(explicit.clone());

            let dir = explicit.parent().unwrap_or_else(|| Path::new(""));
            for import_path in &config.import {
                Config::load_import(import_path, dir)?;
                let import = crate::config_path::resolve_relative_to_dir(import_path, Some(dir));
                if printed.insert(import.clone()) {
                    println!("{}", import.display());
                }
            }
        }

        // Global config is always checked
        let global = Config::global_config_path();
        if global.exists() && printed.insert(global.clone()) {
            println!("{}", global.display());
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
            if self.collect_file(&dir.join(filename), printed)? {
                found_root = true;
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

    /// Print `path` and any files it imports. Returns whether it sets `root = true`.
    fn collect_file(&self, path: &Path, printed: &mut HashSet<PathBuf>) -> Result<bool> {
        if !path.exists() || !printed.insert(path.to_path_buf()) {
            return Ok(false);
        }
        println!("{}", path.display());

        let Ok(content) = std::fs::read_to_string(path) else {
            return Ok(false);
        };
        let Ok(partial) = toml_edit::de::from_str::<PartialConfig>(&content) else {
            return Ok(false);
        };

        self.collect_imports(path, &partial.import, printed);

        Ok(partial.root)
    }

    /// Print the files `path` imports, resolved relative to its directory.
    ///
    /// Tolerant of missing imports, matching how the discovery walk has
    /// always reported them.
    fn collect_imports(&self, path: &Path, imports: &[String], printed: &mut HashSet<PathBuf>) {
        let dir = path.parent().unwrap_or_else(|| Path::new(""));
        for import_path in imports {
            let import = crate::config_path::resolve_relative_to_dir(import_path, Some(dir));
            if import.exists() && printed.insert(import.clone()) {
                println!("{}", import.display());
            }
        }
    }
}
