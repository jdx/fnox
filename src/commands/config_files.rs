use crate::config::{Config, all_config_filenames};
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
            let path = dir.join(filename);
            if path.exists() && printed.insert(path.clone()) {
                println!("{}", path.display());

                if let Ok(content) = std::fs::read_to_string(&path)
                    && let Ok(partial) = toml_edit::de::from_str::<PartialConfig>(&content)
                {
                    // Print imported config files
                    for import_path in &partial.import {
                        let import = if Path::new(import_path).is_absolute() {
                            PathBuf::from(import_path)
                        } else {
                            dir.join(import_path)
                        };
                        if import.exists() && printed.insert(import.clone()) {
                            println!("{}", import.display());
                        }
                    }

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
}
