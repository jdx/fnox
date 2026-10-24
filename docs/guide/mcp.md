---
description: "Run fnox as an MCP server so AI agents can fetch selected secrets or run commands with them, with allowlists for tools and secrets and redacted output."
---

# MCP server

`fnox mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio. An AI agent such as Claude Code connects to it and can ask for secrets, or run a command with secrets injected, instead of finding them in its own environment.

You decide which tools the agent gets and which secrets it can reach.

## Set up

Add the server to your agent's MCP config. For Claude Code, create `.mcp.json` in the project:

```json
{
  "mcpServers": {
    "fnox": {
      "command": "fnox",
      "args": ["mcp"]
    }
  }
}
```

Use `"args": ["-P", "staging", "mcp"]` to serve a profile. The agent must start the server from the project directory so fnox finds `fnox.toml`, or pass `-c <path>`.

The server never prompts, so sign in to your providers (for example `op signin`) before starting the agent.

## Choose what the agent can do

```toml
[mcp]
tools = ["exec"]                         # default: ["get_secret", "exec"]
secrets = ["GITHUB_TOKEN", "NPM_TOKEN"]  # default: every secret in the profile
```

| Tool         | What the agent gets                                                                                           |
| ------------ | ------------------------------------------------------------------------------------------------------------- |
| `get_secret` | The value of one secret, by name.                                                                             |
| `exec`       | Runs a command with the secrets injected and returns its output, with secret values replaced by `[REDACTED]`. |

`secrets` limits both tools: unlisted secrets are never resolved, injected, or returned. Disabled tools aren't advertised to the agent at all.

## How it behaves

- On the first tool call, fnox resolves the allowed secrets in one batch, so you approve one YubiKey touch or SSO prompt per session rather than one per call. `env = false` secrets are resolved only when `get_secret` asks for them.
- Values stay in the server's memory for the session and are gone when the agent disconnects. `as_file` secrets are written to temporary files for the duration of an `exec` call.
- `exec` captures output (up to 1 MiB) instead of sharing the terminal, and times out after `exec_timeout_secs` (default 300).

## What it does and doesn't protect

`exec` without `get_secret` keeps raw values out of the agent's conversation in normal use, and every command it runs is visible to you. It is **not** isolation: the agent chooses the command, and a command can encode or send a value somewhere. Redaction matches literal values only, so base64 or other transformed output isn't caught. You can turn redaction off with `redact_output = false`, but there's rarely a reason to.

Shell integration is a separate channel. If your interactive shell already has secrets loaded, an agent started from it can read them regardless of `[mcp]`. Set `env = "exec"` to keep secrets out of the shell (see [running commands](/guide/running-commands#choose-which-secrets-reach-a-command)).

For stronger isolation, give the agent API access through the [credential proxy](/guide/proxy) instead, and run it with [`fnox proxy run --sandbox`](/guide/proxy#sandbox).

## See also

- [Credential proxy](/guide/proxy): the agent never sees real credentials.
- [Configuration reference](/reference/configuration#mcp-server-settings): every `[mcp]` field.
- [`fnox mcp` reference](/cli/mcp).
