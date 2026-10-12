---
description: "Write a custom fnox provider in Lua, install plugins from git, and pass options and credentials to them."
---

# Lua plugins

When no built-in provider fits, such as an in-house secrets API, a niche vault, or a CLI that fnox doesn't wrap, you can write the provider as a Lua 5.4 plugin. A plugin is a `provider.lua` file that returns a table of hooks. fnox calls the hooks to read, store, or encrypt values and gives them modules for HTTP, JSON, and running commands.

## Quick start

Create `plugins/corp.lua` next to `fnox.toml`:

```lua
local http = require("fnox.http")
local json = require("fnox.json")

return {
  get = function(ctx, ref)
    local resp = http.get(ctx.options.endpoint .. "/v1/secrets/" .. ref, {
      headers = { Authorization = "Bearer " .. os.getenv("CORP_TOKEN") },
    })
    if resp.status == 404 then return nil end
    if not resp.ok then error("corp API returned " .. resp.status) end
    return json.decode(resp.body).value
  end,
}
```

Then point a provider at it:

```toml
[providers.corp]
type = "lua"
plugin = "./plugins/corp.lua"
options = { endpoint = "https://secrets.corp.example" }

[secrets]
DATABASE_URL = { provider = "corp", value = "prod/database-url" }
```

```sh
fnox get DATABASE_URL
```

fnox resolves a relative `plugin` path from the config file that declares the provider, so the plugin works from any subdirectory.

## Provider configuration

| Field          | Required | Description                                                                                                                                                                             |
| -------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `plugin`       | Yes      | An installed plugin name, or a path to a `.lua` file or plugin directory. Values containing `/`, starting with `.` or `~`, or ending in `.lua` are paths.                               |
| `options`      | No       | A table of string settings, passed to hooks as `ctx.options`. Values may be [secret references](/guide/profiles#secret-references-in-provider-config), resolved before the plugin runs. |
| `auth_command` | No       | Command fnox offers to run when the plugin raises an authentication error.                                                                                                              |

`fnox provider add corp lua` adds a provider whose `plugin` is the provider name. Pass `--plugin <name-or-path>` to use a different value.

## Installing plugins

To share a plugin across projects, publish it as a git repository with `provider.lua` at its root. Declare it under `[plugins]`, and fnox installs it the first time a provider uses it:

```toml
[plugins]
corp = "acme/fnox-plugin-corp#v1.2.0"

[providers.corp]
type = "lua"
plugin = "corp"
```

A source is a git URL, optionally followed by `#<ref>` to pin a tag, branch, or commit. `owner/repo` is shorthand for `https://github.com/owner/repo.git`. fnox clones plugins into `~/.local/share/fnox/plugins/<name>`; set `FNOX_DATA_DIR` or `FNOX_PLUGINS_DIR` to change the location.

Manage installed plugins with [`fnox plugin`](/cli/plugin):

```sh
fnox plugin install                       # install every plugin declared under [plugins]
fnox plugin install corp acme/fnox-plugin-corp#v1.2.0
fnox plugin ls                            # installed plugins, their source and revision
fnox plugin update                        # move each plugin to its declared ref, or the default branch
fnox plugin link corp ~/src/fnox-plugin-corp   # use a local checkout while developing
fnox plugin uninstall corp
```

`fnox plugin update` skips linked plugins, so you can edit a linked checkout without fnox resetting it.

::: warning
A plugin runs with your user's permissions, like any provider CLI fnox runs. Install plugins only from sources you trust, and pin a tag or commit for shared configs.
:::

## Hooks

The returned table must define `get`; the other hooks are optional. Each hook receives `ctx` first:

| `ctx` field      | Value                                   |
| ---------------- | --------------------------------------- |
| `ctx.provider`   | The provider name from `fnox.toml`      |
| `ctx.options`    | The provider's resolved `options` table |
| `ctx.plugin_dir` | The plugin's directory                  |

| Hook                   | Return value                                              | Used by                                    |
| ---------------------- | --------------------------------------------------------- | ------------------------------------------ |
| `get(ctx, ref)`        | The secret value, or `nil` if it does not exist           | `get`, `exec`, `export`, shell integration |
| `get_batch(ctx, refs)` | A table mapping each found ref to its value               | Resolving several secrets at once          |
| `put(ctx, key, value)` | The reference to save in `fnox.toml` (defaults to `key`)  | `fnox set`                                 |
| `encrypt(ctx, value)`  | Ciphertext to save in `fnox.toml`; `get` then decrypts it | `fnox set`, `fnox import`, `reencrypt`     |
| `test(ctx)`            | Nothing; raise an error if the backend is unreachable     | `fnox provider test`                       |

`ref` is the secret's `value` from `fnox.toml`. Without `get_batch`, fnox calls `get` for each secret, up to 10 at a time. Define `get_batch` when the backend can return many values in one request; `refs` is a list of unique references.

A plugin that defines `encrypt` is an encryption provider. One that defines `put` stores values remotely. A plugin with neither is read-only, and `fnox set` reports an error.

## Errors and authentication

Raise an error with `error("message")` to fail a lookup; fnox reports the message with the provider name. Return `nil` from `get` when the secret doesn't exist, so `if_missing` and `default` apply.

When the backend rejects the user's credentials, raise `require("fnox").auth_error(message)` instead. fnox reports an authentication failure and, in an interactive terminal, offers to run the provider's `auth_command`:

```lua
local fnox = require("fnox")

-- inside a hook
if resp.status == 401 then
  fnox.auth_error("session expired; run `corp login`")
end
```

```toml
[providers.corp]
type = "lua"
plugin = "corp"
auth_command = "corp login"
```

## Modules

Plugins can `require` Lua's standard library, their own modules (from the plugin directory or its `lib/` subdirectory), and these fnox modules:

| Module        | Functions                                                                                                                                                                                                                                                                                                                    |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fnox`        | `auth_error(message)`, `version`                                                                                                                                                                                                                                                                                             |
| `fnox.http`   | `get(url, opts)`, `delete(url, opts)`, `post(url, body, opts)`, `put(url, body, opts)`, `patch(url, body, opts)`, `request(opts)`. `opts` may set `headers`, `query`, `body`, `timeout` (seconds), and for `request`, `method` and `url`. Each returns `{ status, ok, headers, body }` and does not raise on error statuses. |
| `fnox.json`   | `encode(value)`, `decode(string)`. JSON `null` decodes to `nil`.                                                                                                                                                                                                                                                             |
| `fnox.cmd`    | `exec(command, opts)` returns trimmed stdout and raises on a non-zero exit. `run(command, opts)` returns `{ status, ok, stdout, stderr }`. `command` is an argv table (no shell) or a string run by `sh -c` (`cmd /C` on Windows). `opts` may set `env`, `cwd`, and `stdin`.                                                 |
| `fnox.log`    | `trace`, `debug`, `info`, `warn`, `error`; messages go to fnox's stderr log. `debug` and `trace` appear with `--verbose`.                                                                                                                                                                                                    |
| `fnox.base64` | `encode(string)`, `decode(string)`                                                                                                                                                                                                                                                                                           |

HTTP requests use fnox's `http_timeout` setting unless `opts.timeout` is set.

## Example: wrap a CLI

This plugin reads secrets with a vendor CLI and stores them with `put`:

```lua
local cmd = require("fnox.cmd")
local fnox = require("fnox")

local function vault_args(ctx, ...)
  return { "acme-vault", "--vault", ctx.options.vault, ... }
end

return {
  get = function(ctx, ref)
    local result = cmd.run(vault_args(ctx, "read", ref))
    if result.ok then return (result.stdout:gsub("\n$", "")) end
    if result.stderr:find("not found") then return nil end
    if result.stderr:find("not logged in") then fnox.auth_error("run `acme-vault login`") end
    error(result.stderr)
  end,

  put = function(ctx, key, value)
    cmd.exec(vault_args(ctx, "write", key, "--stdin"), { stdin = value })
    return key
  end,

  test = function(ctx)
    cmd.exec(vault_args(ctx, "whoami"))
  end,
}
```

```toml
[providers.acme]
type = "lua"
plugin = "./plugins/acme.lua"
options = { vault = "engineering" }
auth_command = "acme-vault login"
```

## Limitations

- Option values are strings. Parse numbers and lists in the plugin.
- fnox may load a plugin more than once in a command. Don't rely on module-level variables to keep state between lookups.
- There is no central plugin registry yet; install plugins by git URL or `owner/repo`.
