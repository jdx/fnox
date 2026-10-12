//! Lua provider plugin management.
//!
//! Plugins are git repositories (or local directories) containing a
//! `provider.lua` entry file. Installed plugins live in
//! [`env::FNOX_PLUGINS_DIR`], one subdirectory per plugin name. A linked
//! plugin is a symlink to a local checkout, which `update` leaves alone.

use crate::env;
use crate::error::{FnoxError, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// File every plugin must provide; it returns the provider's hook table.
pub const ENTRY_FILE: &str = "provider.lua";

/// Where a plugin is installed from: a git URL and an optional ref
/// (tag, branch, or commit) to check out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSource {
    pub url: String,
    pub git_ref: Option<String>,
}

impl PluginSource {
    /// Parse `<url>[#ref]`. `owner/repo` is shorthand for
    /// `https://github.com/owner/repo.git`.
    pub fn parse(source: &str) -> Result<Self> {
        let source = source.trim();
        let (url, git_ref) = match source.rsplit_once('#') {
            Some((url, git_ref)) if !git_ref.is_empty() => (url, Some(git_ref.to_string())),
            Some((url, _)) => (url, None),
            None => (source, None),
        };
        if url.is_empty() {
            return Err(FnoxError::Config(format!(
                "invalid plugin source '{source}': missing URL"
            )));
        }
        let url = if is_github_shorthand(url) {
            format!("https://github.com/{url}.git")
        } else {
            url.to_string()
        };
        Ok(Self { url, git_ref })
    }
}

impl std::fmt::Display for PluginSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.git_ref {
            Some(git_ref) => write!(f, "{}#{git_ref}", self.url),
            None => write!(f, "{}", self.url),
        }
    }
}

fn is_github_shorthand(url: &str) -> bool {
    let mut parts = url.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let valid = |part: &str| {
        !part.is_empty()
            && !part.starts_with('.')
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    valid(owner) && valid(repo)
}

/// Plugin names become directory names, so keep them to a safe character set.
pub fn validate_name(name: &str) -> Result<()> {
    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if valid {
        Ok(())
    } else {
        Err(FnoxError::Config(format!(
            "invalid plugin name '{name}': use letters, digits, '-', '_' or '.', starting with a letter or digit"
        )))
    }
}

pub fn plugins_dir() -> &'static Path {
    &env::FNOX_PLUGINS_DIR
}

pub fn plugin_dir(name: &str) -> PathBuf {
    plugins_dir().join(name)
}

/// Whether a plugin directory (or link) exists for `name`.
pub fn is_installed(name: &str) -> bool {
    plugin_dir(name).symlink_metadata().is_ok()
}

/// An installed plugin, as reported by `fnox plugin ls`.
#[derive(Debug, Clone)]
pub struct InstalledPlugin {
    pub name: String,
    pub path: PathBuf,
    /// Target of the link, when installed with `fnox plugin link`
    pub link_target: Option<PathBuf>,
    pub url: Option<String>,
    pub revision: Option<String>,
}

/// List installed plugins, sorted by name.
pub fn list_installed() -> Result<Vec<InstalledPlugin>> {
    let dir = plugins_dir();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut plugins = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if validate_name(&name).is_err() {
            // Skips temporary install directories and stray files
            continue;
        }
        let path = entry.path();
        let link_target = std::fs::read_link(&path).ok();
        let (url, revision) = if link_target.is_none() {
            (
                git_output_sync(&path, &["remote", "get-url", "origin"]),
                git_output_sync(&path, &["rev-parse", "--short", "HEAD"]),
            )
        } else {
            (None, None)
        };
        plugins.push(InstalledPlugin {
            name,
            path,
            link_target,
            url,
            revision,
        });
    }
    plugins.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(plugins)
}

fn git_output_sync(dir: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn git(name: &str, dir: Option<&Path>, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("git");
    if let Some(dir) = dir {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(args)
        // Never block on a credential prompt; fail with git's message instead.
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::null());
    tracing::debug!("git {}", args.join(" "));
    let output = cmd.output().await.map_err(|e| FnoxError::Plugin {
        plugin: name.to_string(),
        details: format!("failed to run git: {e}"),
        help: "Install git to manage fnox plugins".to_string(),
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(FnoxError::Plugin {
        plugin: name.to_string(),
        details: format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        help: "Check the plugin URL and ref, and that you can access the repository".to_string(),
    })
}

/// Check out `git_ref` (or the remote's default branch) in `dir`.
async fn checkout(name: &str, dir: &Path, git_ref: Option<&str>) -> Result<()> {
    let target = git_ref.unwrap_or("HEAD");
    git(name, Some(dir), &["fetch", "--quiet", "origin", target]).await?;
    git(
        name,
        Some(dir),
        &["checkout", "--quiet", "--detach", "FETCH_HEAD"],
    )
    .await
}

fn ensure_entry_file(name: &str, dir: &Path) -> Result<()> {
    if dir.join(ENTRY_FILE).is_file() {
        return Ok(());
    }
    Err(FnoxError::Plugin {
        plugin: name.to_string(),
        details: format!("{} has no {ENTRY_FILE}", dir.display()),
        help: format!("A fnox plugin must have a {ENTRY_FILE} file at its root"),
    })
}

/// Clone a plugin into the plugins directory. Fails if it is already installed
/// unless `force` is set, in which case the existing install is replaced.
pub async fn install(name: &str, source: &PluginSource, force: bool) -> Result<PathBuf> {
    validate_name(name)?;
    let dest = plugin_dir(name);
    if is_installed(name) && !force {
        return Err(FnoxError::Plugin {
            plugin: name.to_string(),
            details: "already installed".to_string(),
            help: format!("Use `fnox plugin update {name}`, or `--force` to reinstall"),
        });
    }
    std::fs::create_dir_all(plugins_dir()).map_err(|e| FnoxError::CreateDirFailed {
        path: plugins_dir().to_path_buf(),
        source: e,
    })?;

    // Clone next to the destination and move it into place once it is
    // complete, so an interrupted install never leaves a half-cloned plugin.
    let tmp = tempfile::Builder::new()
        .prefix(&format!(".{name}-"))
        .tempdir_in(plugins_dir())?;
    let checkout_dir = tmp.path().join("plugin");
    let checkout_str = checkout_dir.to_string_lossy().to_string();
    git(
        name,
        None,
        &["clone", "--quiet", "--", &source.url, &checkout_str],
    )
    .await?;
    if source.git_ref.is_some() {
        checkout(name, &checkout_dir, source.git_ref.as_deref()).await?;
    }
    ensure_entry_file(name, &checkout_dir)?;

    if force {
        remove(&dest)?;
    }
    match std::fs::rename(&checkout_dir, &dest) {
        Ok(()) => {}
        // Another fnox process finished installing the same plugin first
        Err(_) if !force && dest.join(ENTRY_FILE).is_file() => {}
        Err(e) => return Err(e.into()),
    }
    Ok(dest)
}

/// Update an installed plugin to `source` (or its current remote's default
/// branch when no source is known). Linked plugins are not touched.
pub async fn update(name: &str, source: Option<&PluginSource>) -> Result<UpdateOutcome> {
    validate_name(name)?;
    let dir = plugin_dir(name);
    if !is_installed(name) {
        return Err(not_installed(name));
    }
    if std::fs::read_link(&dir).is_ok() {
        return Ok(UpdateOutcome::Linked);
    }
    if let Some(source) = source {
        git(
            name,
            Some(&dir),
            &["remote", "set-url", "origin", &source.url],
        )
        .await?;
    }
    checkout(name, &dir, source.and_then(|s| s.git_ref.as_deref())).await?;
    ensure_entry_file(name, &dir)?;
    Ok(UpdateOutcome::Updated)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated,
    Linked,
}

/// Remove an installed or linked plugin.
pub fn uninstall(name: &str) -> Result<()> {
    validate_name(name)?;
    if !is_installed(name) {
        return Err(not_installed(name));
    }
    remove(&plugin_dir(name))
}

fn remove(path: &Path) -> Result<()> {
    match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(meta) if meta.is_dir() => Ok(std::fs::remove_dir_all(path)?),
        // Symlinks (including directory symlinks on Windows) and files
        Ok(_) => {
            #[cfg(windows)]
            if std::fs::remove_dir(path).is_ok() {
                return Ok(());
            }
            Ok(std::fs::remove_file(path)?)
        }
    }
}

/// Install a plugin as a link to a local directory, for plugin development.
pub fn link(name: &str, target: &Path, force: bool) -> Result<PathBuf> {
    validate_name(name)?;
    let target = std::fs::canonicalize(target).map_err(|e| FnoxError::Plugin {
        plugin: name.to_string(),
        details: format!("cannot link {}: {e}", target.display()),
        help: "Pass the path to a plugin directory".to_string(),
    })?;
    ensure_entry_file(name, &target)?;
    let dest = plugin_dir(name);
    if is_installed(name) {
        if !force {
            return Err(FnoxError::Plugin {
                plugin: name.to_string(),
                details: "already installed".to_string(),
                help: "Use `--force` to replace it with a link".to_string(),
            });
        }
        remove(&dest)?;
    }
    std::fs::create_dir_all(plugins_dir()).map_err(|e| FnoxError::CreateDirFailed {
        path: plugins_dir().to_path_buf(),
        source: e,
    })?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &dest)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&target, &dest)?;
    Ok(dest)
}

/// Return the directory of an installed plugin, installing it first from
/// `declared` (its `[plugins]` source) when it is missing.
pub async fn ensure_installed(name: &str, declared: Option<&str>) -> Result<PathBuf> {
    validate_name(name)?;
    if is_installed(name) {
        return Ok(plugin_dir(name));
    }
    let Some(declared) = declared else {
        return Err(not_installed(name));
    };
    let source = PluginSource::parse(declared)?;
    tracing::info!("installing plugin '{name}' from {source}");
    install(name, &source, false).await
}

fn not_installed(name: &str) -> FnoxError {
    FnoxError::Plugin {
        plugin: name.to_string(),
        details: "not installed".to_string(),
        help: format!(
            "Install it with `fnox plugin install {name} <git-url>`, or declare it under [plugins] in fnox.toml"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sources() {
        assert_eq!(
            PluginSource::parse("jdx/fnox-plugin-demo").unwrap(),
            PluginSource {
                url: "https://github.com/jdx/fnox-plugin-demo.git".to_string(),
                git_ref: None,
            }
        );
        assert_eq!(
            PluginSource::parse("https://example.com/p.git#v1.2.0").unwrap(),
            PluginSource {
                url: "https://example.com/p.git".to_string(),
                git_ref: Some("v1.2.0".to_string()),
            }
        );
        assert_eq!(
            PluginSource::parse("git@github.com:org/repo.git").unwrap(),
            PluginSource {
                url: "git@github.com:org/repo.git".to_string(),
                git_ref: None,
            }
        );
        assert_eq!(
            PluginSource::parse("/srv/plugins/corp").unwrap().url,
            "/srv/plugins/corp"
        );
        assert!(PluginSource::parse("#v1").is_err());
    }

    #[test]
    fn validates_names() {
        assert!(validate_name("corp").is_ok());
        assert!(validate_name("corp-secrets_2.x").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("../evil").is_err());
        assert!(validate_name("a/b").is_err());
    }
}
