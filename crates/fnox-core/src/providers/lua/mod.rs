//! Provider backed by a Lua 5.4 plugin.
//!
//! A plugin is a Lua file (`provider.lua` at the root of a plugin directory)
//! that returns a table of hooks:
//!
//! ```lua
//! return {
//!   get = function(ctx, ref) ... end,         -- required: value or nil
//!   get_batch = function(ctx, refs) ... end,  -- optional: { [ref] = value }
//!   put = function(ctx, key, value) ... end,  -- optional: store remotely, return ref
//!   encrypt = function(ctx, value) ... end,   -- optional: return ciphertext
//!   test = function(ctx) ... end,             -- optional: raise on failure
//! }
//! ```
//!
//! `ctx` carries the provider name, the plugin directory, and the provider's
//! `options` table. Host modules (`fnox`, `fnox.http`, `fnox.json`, `fnox.cmd`,
//! `fnox.log`, `fnox.base64`) are available through `require`.

mod host;

use crate::error::{FnoxError, Result};
use crate::plugins;
use crate::providers::{Provider, ProviderCapability};
use async_trait::async_trait;
use indexmap::IndexMap;
use mlua::{Function, Lua, LuaSerdeExt, Table, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::OnceCell;

const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/lua";

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

/// How the `plugin` field was given: an installed plugin name or a path.
#[derive(Debug, Clone)]
enum PluginLocation {
    Path(PathBuf),
    Installed {
        name: String,
        /// `[plugins]` source used to install the plugin on first use
        declared: Option<String>,
    },
}

impl PluginLocation {
    fn parse(plugin: &str) -> Self {
        let looks_like_path = plugin.contains('/')
            || plugin.contains('\\')
            || plugin.starts_with('.')
            || plugin.starts_with('~')
            || plugin.ends_with(".lua");
        if looks_like_path {
            Self::Path(crate::config_path::expand_tilde(plugin))
        } else {
            Self::Installed {
                name: plugin.to_string(),
                declared: None,
            }
        }
    }

    /// Whether `plugin` refers to a file or directory rather than an
    /// installed plugin name.
    pub(crate) fn is_path(plugin: &str) -> bool {
        matches!(Self::parse(plugin), Self::Path(_))
    }
}

/// Whether a `plugin` value is a path (resolved relative to its config file)
/// rather than an installed plugin name.
pub fn plugin_is_path(plugin: &str) -> bool {
    PluginLocation::is_path(plugin)
}

pub struct LuaProvider {
    provider_name: String,
    location: PluginLocation,
    options: IndexMap<String, String>,
    runtime: OnceCell<Runtime>,
}

/// A loaded plugin: its Lua state, hook table, and the `ctx` passed to hooks.
struct Runtime {
    // Keeps the state alive alongside the handles below
    _lua: Lua,
    hooks: Table,
    ctx: Table,
}

impl LuaProvider {
    pub fn new(
        provider_name: String,
        plugin: String,
        options: IndexMap<String, String>,
    ) -> Result<Self> {
        if plugin.trim().is_empty() {
            return Err(FnoxError::Config(format!(
                "provider '{provider_name}': `plugin` must not be empty"
            )));
        }
        let location = PluginLocation::parse(&plugin);
        if let PluginLocation::Installed { name, .. } = &location {
            plugins::validate_name(name)?;
        }
        Ok(Self {
            provider_name,
            location,
            options,
            runtime: OnceCell::new(),
        })
    }

    /// Set the `[plugins]` source to install from when the plugin is missing.
    pub fn with_declared_source(mut self, source: Option<String>) -> Self {
        if let PluginLocation::Installed { declared, .. } = &mut self.location {
            *declared = source;
        }
        self
    }

    fn display_name(&self) -> String {
        match &self.location {
            PluginLocation::Path(path) => path.display().to_string(),
            PluginLocation::Installed { name, .. } => name.clone(),
        }
    }

    fn plugin_error(&self, details: impl Into<String>, help: impl Into<String>) -> FnoxError {
        FnoxError::Plugin {
            plugin: self.display_name(),
            details: details.into(),
            help: help.into(),
        }
    }

    /// Locate the plugin's entry file and the directory added to `package.path`.
    async fn entry(&self) -> Result<(PathBuf, PathBuf)> {
        let dir = match &self.location {
            PluginLocation::Installed { name, declared } => {
                plugins::ensure_installed(name, declared.as_deref()).await?
            }
            PluginLocation::Path(path) if path.is_file() => {
                let dir = path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));
                return Ok((path.clone(), dir));
            }
            PluginLocation::Path(path) if path.is_dir() => path.clone(),
            PluginLocation::Path(path) => {
                return Err(self.plugin_error(
                    format!("{} does not exist", path.display()),
                    "Relative plugin paths are resolved from the config file that declares the provider",
                ));
            }
        };
        let entry = dir.join(plugins::ENTRY_FILE);
        if !entry.is_file() {
            return Err(self.plugin_error(
                format!("{} has no {}", dir.display(), plugins::ENTRY_FILE),
                format!(
                    "A fnox plugin must have a {} file at its root",
                    plugins::ENTRY_FILE
                ),
            ));
        }
        Ok((entry, dir))
    }

    async fn runtime(&self) -> Result<&Runtime> {
        self.runtime.get_or_try_init(|| self.load()).await
    }

    /// Load the plugin from synchronous code, such as `capabilities()`.
    ///
    /// Loading may install the plugin or run its top-level code, which needs
    /// an async runtime, so it runs on a scoped thread with its own runtime.
    fn runtime_blocking(&self) -> Option<&Runtime> {
        if let Some(runtime) = self.runtime.get() {
            return Some(runtime);
        }
        let loaded = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()?;
                    rt.block_on(self.load())
                        .inspect_err(|e| tracing::debug!("failed to load Lua plugin: {e}"))
                        .ok()
                })
                .join()
                .ok()
                .flatten()
        })?;
        // Another caller may have loaded it meanwhile; either copy is fine.
        let _ = self.runtime.set(loaded);
        self.runtime.get()
    }

    async fn load(&self) -> Result<Runtime> {
        let (entry, dir) = self.entry().await?;
        let source = tokio::fs::read_to_string(&entry).await.map_err(|e| {
            self.plugin_error(
                format!("failed to read {}: {e}", entry.display()),
                "Check the plugin path",
            )
        })?;

        let lua = Lua::new();
        let load_err = |e: mlua::Error| {
            self.plugin_error(
                format!("failed to load: {}", host::error_message(&e)),
                format!("Fix the error in {}", entry.display()),
            )
        };
        host::register(&lua, &self.provider_name).map_err(load_err)?;
        set_package_path(&lua, &dir).map_err(load_err)?;

        let hooks: Value = lua
            .load(source)
            .set_name(format!("@{}", entry.display()))
            .call_async(())
            .await
            .map_err(load_err)?;
        let Value::Table(hooks) = hooks else {
            return Err(self.plugin_error(
                format!(
                    "{} must return a table of hooks, got {}",
                    entry.display(),
                    hooks.type_name()
                ),
                "End the file with `return { get = function(ctx, ref) ... end }`",
            ));
        };
        if hook(&hooks, "get").map_err(load_err)?.is_none() {
            return Err(self.plugin_error(
                "missing required `get` hook",
                "Add `get = function(ctx, ref) ... end` to the returned table",
            ));
        }

        let ctx = lua.create_table().map_err(load_err)?;
        let options = lua.to_value(&self.options).map_err(load_err)?;
        ctx.set("provider", self.provider_name.as_str())
            .and_then(|_| ctx.set("plugin_dir", dir.to_string_lossy().to_string()))
            .and_then(|_| ctx.set("options", options))
            .map_err(load_err)?;

        Ok(Runtime {
            _lua: lua,
            hooks,
            ctx,
        })
    }

    /// Convert an error raised by a hook into a provider error.
    fn hook_error(&self, hook_name: &str, err: &mlua::Error) -> FnoxError {
        let message = host::error_message(err);
        if host::is_auth_error(err) {
            return FnoxError::ProviderAuthFailed {
                provider: self.provider_name.clone(),
                details: message,
                hint:
                    "Authenticate with the plugin's backend, or set `auth_command` on the provider"
                        .to_string(),
                url: PROVIDER_URL.to_string(),
            };
        }
        FnoxError::Provider(format!(
            "{}: {hook_name} hook failed: {message}",
            self.provider_name
        ))
    }

    fn not_found(&self, reference: &str) -> FnoxError {
        FnoxError::ProviderSecretNotFound {
            provider: self.provider_name.clone(),
            secret: reference.to_string(),
            hint: format!("The {} plugin returned nil", self.display_name()),
            url: PROVIDER_URL.to_string(),
        }
    }

    async fn call_string_hook(
        &self,
        hook_name: &str,
        args: impl mlua::IntoLuaMulti,
    ) -> Result<Option<String>> {
        let runtime = self.runtime().await?;
        let Some(function) =
            hook(&runtime.hooks, hook_name).map_err(|e| self.hook_error(hook_name, &e))?
        else {
            return Err(FnoxError::Provider(format!(
                "{}: plugin does not implement `{hook_name}`",
                self.provider_name
            )));
        };
        let value: Value = function
            .call_async(args)
            .await
            .map_err(|e| self.hook_error(hook_name, &e))?;
        match value {
            Value::Nil => Ok(None),
            Value::String(s) => Ok(Some(
                s.to_str()
                    .map_err(|e| self.hook_error(hook_name, &e))?
                    .to_string(),
            )),
            Value::Integer(_) | Value::Number(_) | Value::Boolean(_) => Ok(Some(
                value
                    .to_string()
                    .map_err(|e| self.hook_error(hook_name, &e))?,
            )),
            other => Err(FnoxError::Provider(format!(
                "{}: {hook_name} hook must return a string or nil, got {}",
                self.provider_name,
                other.type_name()
            ))),
        }
    }

    async fn has_hook(&self, hook_name: &str) -> Result<bool> {
        let runtime = self.runtime().await?;
        Ok(hook(&runtime.hooks, hook_name)
            .map_err(|e| self.hook_error(hook_name, &e))?
            .is_some())
    }

    async fn get_batch_with_hook(
        &self,
        function: Function,
        ctx: Table,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let mut refs: Vec<&str> = secrets.iter().map(|(_, r)| r.as_str()).collect();
        refs.sort_unstable();
        refs.dedup();

        let result: mlua::Result<HashMap<String, Value>> = function.call_async((ctx, refs)).await;
        let values = match result {
            Ok(values) => values,
            Err(e) => {
                let err = self.hook_error("get_batch", &e);
                return secrets
                    .iter()
                    .map(|(key, _)| {
                        let mapped =
                            err.map_batch_error(key, &self.provider_name, "", PROVIDER_URL);
                        (key.clone(), Err(mapped))
                    })
                    .collect();
            }
        };
        secrets
            .iter()
            .map(|(key, reference)| {
                let value = match values.get(reference) {
                    None | Some(Value::Nil) => Err(self.not_found(reference)),
                    Some(Value::String(s)) => s
                        .to_str()
                        .map(|s| s.to_string())
                        .map_err(|e| self.hook_error("get_batch", &e)),
                    Some(other) => Err(FnoxError::Provider(format!(
                        "{}: get_batch hook must map refs to strings, got {} for '{reference}'",
                        self.provider_name,
                        other.type_name()
                    ))),
                };
                (key.clone(), value)
            })
            .collect()
    }
}

fn hook(hooks: &Table, name: &str) -> mlua::Result<Option<Function>> {
    match hooks.get::<Value>(name)? {
        Value::Nil => Ok(None),
        Value::Function(f) => Ok(Some(f)),
        other => Err(mlua::Error::runtime(format!(
            "hook `{name}` must be a function, got {}",
            other.type_name()
        ))),
    }
}

/// Let plugins `require` their own modules from the plugin directory.
fn set_package_path(lua: &Lua, dir: &Path) -> mlua::Result<()> {
    let package: Table = lua.globals().get("package")?;
    let current: String = package.get("path")?;
    let dir = dir.to_string_lossy();
    let sep = std::path::MAIN_SEPARATOR;
    package.set(
        "path",
        format!("{dir}{sep}?.lua;{dir}{sep}?{sep}init.lua;{dir}{sep}lib{sep}?.lua;{current}"),
    )
}

#[async_trait]
impl Provider for LuaProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        // Capabilities follow the hooks the plugin defines. If the plugin
        // cannot load, report read-only and let the next call surface the error.
        let Some(runtime) = self.runtime_blocking() else {
            return vec![ProviderCapability::RemoteRead];
        };
        let defined = |name| matches!(hook(&runtime.hooks, name), Ok(Some(_)));
        if defined("encrypt") {
            vec![ProviderCapability::Encryption]
        } else if defined("put") {
            vec![ProviderCapability::RemoteStorage]
        } else {
            vec![ProviderCapability::RemoteRead]
        }
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        let ctx = self.runtime().await?.ctx.clone();
        self.call_string_hook("get", (ctx, value))
            .await?
            .ok_or_else(|| self.not_found(value))
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let runtime = match self.runtime().await {
            Ok(runtime) => runtime,
            Err(e) => {
                return secrets
                    .iter()
                    .map(|(key, _)| {
                        let mapped = e.map_batch_error(key, &self.provider_name, "", PROVIDER_URL);
                        (key.clone(), Err(mapped))
                    })
                    .collect();
            }
        };
        match hook(&runtime.hooks, "get_batch") {
            Ok(Some(function)) => {
                self.get_batch_with_hook(function, runtime.ctx.clone(), secrets)
                    .await
            }
            _ => crate::providers::get_secrets_concurrent(self, secrets, 10).await,
        }
    }

    async fn encrypt(&self, value: &str) -> Result<String> {
        let ctx = self.runtime().await?.ctx.clone();
        self.call_string_hook("encrypt", (ctx, value))
            .await?
            .ok_or_else(|| {
                FnoxError::Provider(format!("{}: encrypt hook returned nil", self.provider_name))
            })
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        let ctx = self.runtime().await?.ctx.clone();
        if self.has_hook("put").await? {
            let reference = self.call_string_hook("put", (ctx, key, value)).await?;
            return Ok(reference.unwrap_or_else(|| key.to_string()));
        }
        if self.has_hook("encrypt").await? {
            return self.encrypt(value).await;
        }
        Err(FnoxError::Provider(format!(
            "{}: plugin is read-only (it defines neither `put` nor `encrypt`)",
            self.provider_name
        )))
    }

    async fn test_connection(&self) -> Result<()> {
        let runtime = self.runtime().await?;
        let Some(function) =
            hook(&runtime.hooks, "test").map_err(|e| self.hook_error("test", &e))?
        else {
            return Ok(());
        };
        function
            .call_async::<()>(runtime.ctx.clone())
            .await
            .map_err(|e| self.hook_error("test", &e))
    }
}

#[cfg(test)]
mod tests;
