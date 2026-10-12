//! Host modules exposed to Lua plugins through `require`.
//!
//! - `fnox`: `auth_error(message)` and `version`
//! - `fnox.http`: `request`, `get`, `post`, `put`, `patch`, `delete`
//! - `fnox.json`: `encode`, `decode`
//! - `fnox.cmd`: `exec` (stdout, raises on failure) and `run` (status/stdout/stderr)
//! - `fnox.log`: `trace`, `debug`, `info`, `warn`, `error`
//! - `fnox.base64`: `encode`, `decode`

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use mlua::{ExternalResult, Lua, LuaSerdeExt, Table, Value, Variadic};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

/// Raised by `fnox.auth_error`; mapped to an authentication failure so fnox
/// can offer the provider's `auth_command`.
#[derive(Debug)]
struct AuthError(String);

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuthError {}

pub(super) fn register(lua: &Lua, provider_name: &str) -> mlua::Result<()> {
    let package: Table = lua.globals().get("package")?;
    let loaded: Table = package.get("loaded")?;
    loaded.set("fnox", mod_fnox(lua)?)?;
    loaded.set("fnox.http", mod_http(lua)?)?;
    loaded.set("fnox.json", mod_json(lua)?)?;
    loaded.set("fnox.cmd", mod_cmd(lua)?)?;
    loaded.set("fnox.log", mod_log(lua, provider_name)?)?;
    loaded.set("fnox.base64", mod_base64(lua)?)?;
    Ok(())
}

/// The message of the innermost error, without Lua's stack traceback.
pub(super) fn error_message(err: &mlua::Error) -> String {
    match err {
        mlua::Error::CallbackError { cause, .. } => error_message(cause),
        mlua::Error::BadArgument { cause, .. } => error_message(cause),
        mlua::Error::WithContext { context, cause } => {
            format!("{context}: {}", error_message(cause))
        }
        mlua::Error::ExternalError(e) => e.to_string(),
        mlua::Error::RuntimeError(message) => strip_traceback(message),
        mlua::Error::SyntaxError { message, .. } => strip_traceback(message),
        other => strip_traceback(&other.to_string()),
    }
}

fn strip_traceback(message: &str) -> String {
    message
        .split("\nstack traceback:")
        .next()
        .unwrap_or(message)
        .trim()
        .to_string()
}

/// Whether the error was raised with `fnox.auth_error`.
pub(super) fn is_auth_error(err: &mlua::Error) -> bool {
    match err {
        mlua::Error::CallbackError { cause, .. }
        | mlua::Error::BadArgument { cause, .. }
        | mlua::Error::WithContext { cause, .. } => is_auth_error(cause),
        mlua::Error::ExternalError(e) => e.downcast_ref::<AuthError>().is_some(),
        _ => false,
    }
}

fn mod_fnox(lua: &Lua) -> mlua::Result<Table> {
    let fnox = lua.create_table()?;
    fnox.set(
        "auth_error",
        lua.create_function(|_, message: String| -> mlua::Result<()> {
            Err(mlua::Error::external(AuthError(message)))
        })?,
    )?;
    fnox.set("version", env!("CARGO_PKG_VERSION"))?;
    Ok(fnox)
}

fn mod_json(lua: &Lua) -> mlua::Result<Table> {
    let json = lua.create_table()?;
    json.set(
        "encode",
        lua.create_function(|_, value: Value| serde_json::to_string(&value).into_lua_err())?,
    )?;
    json.set(
        "decode",
        lua.create_function(|lua, input: String| {
            let value: serde_json::Value = serde_json::from_str(&input).into_lua_err()?;
            lua.to_value_with(
                &value,
                mlua::serde::SerializeOptions::new()
                    .serialize_none_to_null(false)
                    .serialize_unit_to_null(false),
            )
        })?,
    )?;
    Ok(json)
}

fn mod_base64(lua: &Lua) -> mlua::Result<Table> {
    let b64 = lua.create_table()?;
    b64.set(
        "encode",
        lua.create_function(|_, input: mlua::LuaString| Ok(BASE64.encode(input.as_bytes())))?,
    )?;
    b64.set(
        "decode",
        lua.create_function(|lua, input: String| {
            let bytes = BASE64.decode(input.trim()).into_lua_err()?;
            lua.create_string(bytes)
        })?,
    )?;
    Ok(b64)
}

fn mod_log(lua: &Lua, provider_name: &str) -> mlua::Result<Table> {
    let log = lua.create_table()?;
    macro_rules! level {
        ($name:literal, $macro:ident) => {{
            let provider = provider_name.to_string();
            log.set(
                $name,
                lua.create_function(move |_, args: Variadic<Value>| {
                    let message = join_values(&args)?;
                    tracing::$macro!(target: "fnox::plugin", "{provider}: {message}");
                    Ok(())
                })?,
            )?;
        }};
    }
    level!("trace", trace);
    level!("debug", debug);
    level!("info", info);
    level!("warn", warn);
    level!("error", error);
    Ok(log)
}

fn join_values(values: &[Value]) -> mlua::Result<String> {
    let parts = values
        .iter()
        .map(|v| v.to_string())
        .collect::<mlua::Result<Vec<_>>>()?;
    Ok(parts.join(" "))
}

// ---------------------------------------------------------------------------
// fnox.http
// ---------------------------------------------------------------------------

struct HttpRequest {
    method: reqwest::Method,
    url: String,
    headers: HashMap<String, String>,
    query: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout: Option<std::time::Duration>,
}

impl HttpRequest {
    fn from_table(
        method: Option<&str>,
        url: Option<String>,
        opts: Option<Table>,
    ) -> mlua::Result<Self> {
        let opts_url: Option<String> = match &opts {
            Some(t) => t.get("url")?,
            None => None,
        };
        let url = url
            .or(opts_url)
            .ok_or_else(|| mlua::Error::runtime("http: missing `url`"))?;
        let method = match method {
            Some(m) => m.to_string(),
            None => match &opts {
                Some(t) => t
                    .get::<Option<String>>("method")?
                    .unwrap_or_else(|| "GET".into()),
                None => "GET".into(),
            },
        };
        let method = reqwest::Method::from_bytes(method.to_uppercase().as_bytes())
            .map_err(|_| mlua::Error::runtime(format!("http: invalid method '{method}'")))?;

        let mut req = Self {
            method,
            url,
            headers: HashMap::new(),
            query: Vec::new(),
            body: None,
            timeout: None,
        };
        let Some(opts) = opts else {
            return Ok(req);
        };
        if let Some(headers) = opts.get::<Option<HashMap<String, String>>>("headers")? {
            req.headers = headers;
        }
        if let Some(query) = opts.get::<Option<Table>>("query")? {
            for pair in query.pairs::<String, Value>() {
                let (k, v) = pair?;
                req.query.push((k, v.to_string()?));
            }
        }
        match opts.get::<Value>("body")? {
            Value::Nil => {}
            Value::String(s) => req.body = Some(s.as_bytes().to_vec()),
            other => {
                return Err(mlua::Error::runtime(format!(
                    "http: `body` must be a string (use fnox.json.encode for tables), got {}",
                    other.type_name()
                )));
            }
        }
        if let Some(secs) = opts.get::<Option<f64>>("timeout")? {
            req.timeout = Some(std::time::Duration::from_secs_f64(secs.max(0.0)));
        }
        Ok(req)
    }

    async fn send(self, lua: Lua) -> mlua::Result<Table> {
        // A client per request: plugins may run on short-lived runtimes, and a
        // pooled connection must not outlive the runtime that opened it.
        let client = crate::http::http_client();
        let mut builder = client.request(self.method, &self.url);
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        if !self.query.is_empty() {
            builder = builder.query(&self.query);
        }
        if let Some(body) = self.body {
            builder = builder.body(body);
        }
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        let resp = builder.send().await.into_lua_err()?;
        let status = resp.status().as_u16();
        let headers = lua.create_table()?;
        for (name, value) in resp.headers() {
            if let Ok(value) = value.to_str() {
                headers.set(name.as_str(), value)?;
            }
        }
        let body = resp.bytes().await.into_lua_err()?;
        let result = lua.create_table()?;
        result.set("status", status)?;
        result.set("ok", (200..300).contains(&status))?;
        result.set("headers", headers)?;
        result.set("body", lua.create_string(&body)?)?;
        Ok(result)
    }
}

fn mod_http(lua: &Lua) -> mlua::Result<Table> {
    let http = lua.create_table()?;
    http.set(
        "request",
        lua.create_async_function(|lua, opts: Table| async move {
            HttpRequest::from_table(None, None, Some(opts))?
                .send(lua)
                .await
        })?,
    )?;
    for method in ["get", "delete"] {
        http.set(
            method,
            lua.create_async_function(
                move |lua, (url, opts): (String, Option<Table>)| async move {
                    HttpRequest::from_table(Some(method), Some(url), opts)?
                        .send(lua)
                        .await
                },
            )?,
        )?;
    }
    for method in ["post", "put", "patch"] {
        http.set(
            method,
            lua.create_async_function(
                move |lua, (url, body, opts): (String, Option<mlua::LuaString>, Option<Table>)| async move {
                    let mut req = HttpRequest::from_table(Some(method), Some(url), opts)?;
                    if let Some(body) = body {
                        req.body = Some(body.as_bytes().to_vec());
                    }
                    req.send(lua).await
                },
            )?,
        )?;
    }
    Ok(http)
}

// ---------------------------------------------------------------------------
// fnox.cmd
// ---------------------------------------------------------------------------

struct CmdOutput {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run a command given as an argv table (no shell) or a string (run by the
/// platform shell), with optional `env`, `cwd`, and `stdin` options.
async fn run_command(command: Value, opts: Option<Table>) -> mlua::Result<CmdOutput> {
    let mut cmd = match command {
        Value::String(s) => {
            let line = s.to_str()?.to_string();
            #[cfg(unix)]
            {
                let mut cmd = tokio::process::Command::new("sh");
                cmd.arg("-c").arg(line);
                cmd
            }
            #[cfg(windows)]
            {
                let mut cmd = tokio::process::Command::new("cmd");
                cmd.arg("/C").arg(line);
                cmd
            }
        }
        Value::Table(argv) => {
            let argv: Vec<String> = argv.sequence_values().collect::<mlua::Result<_>>()?;
            let Some((program, args)) = argv.split_first() else {
                return Err(mlua::Error::runtime("cmd: argv table is empty"));
            };
            let mut cmd = tokio::process::Command::new(program);
            cmd.args(args);
            cmd
        }
        other => {
            return Err(mlua::Error::runtime(format!(
                "cmd: expected a command string or argv table, got {}",
                other.type_name()
            )));
        }
    };

    let mut stdin_data = None;
    if let Some(opts) = opts {
        if let Some(env) = opts.get::<Option<HashMap<String, String>>>("env")? {
            cmd.envs(env);
        }
        if let Some(cwd) = opts.get::<Option<String>>("cwd")? {
            cmd.current_dir(cwd);
        }
        stdin_data = opts
            .get::<Option<mlua::LuaString>>("stdin")?
            .map(|s| s.as_bytes().to_vec());
    }
    cmd.stdin(if stdin_data.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut child = cmd.spawn().into_lua_err()?;
    if let Some(data) = stdin_data
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(&data).await.into_lua_err()?;
    }
    let output = child.wait_with_output().await.into_lua_err()?;
    Ok(CmdOutput {
        status: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn mod_cmd(lua: &Lua) -> mlua::Result<Table> {
    let cmd = lua.create_table()?;
    cmd.set(
        "run",
        lua.create_async_function(|lua, (command, opts): (Value, Option<Table>)| async move {
            let output = run_command(command, opts).await?;
            let result = lua.create_table()?;
            result.set("status", output.status)?;
            result.set("ok", output.status == Some(0))?;
            result.set("stdout", lua.create_string(&output.stdout)?)?;
            result.set("stderr", lua.create_string(&output.stderr)?)?;
            Ok(result)
        })?,
    )?;
    cmd.set(
        "exec",
        lua.create_async_function(|lua, (command, opts): (Value, Option<Table>)| async move {
            let output = run_command(command, opts).await?;
            if output.status != Some(0) {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let status = output
                    .status
                    .map_or_else(|| "a signal".to_string(), |code| format!("status {code}"));
                return Err(mlua::Error::runtime(format!(
                    "command exited with {status}: {}",
                    stderr.trim()
                )));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            lua.create_string(stdout.trim_end_matches(['\r', '\n']))
        })?,
    )?;
    Ok(cmd)
}
