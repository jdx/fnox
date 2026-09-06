---
description: "Expose selected secrets and command execution through the fnox MCP server, with explicit tool and secret allowlists."
---

# MCP server

`fnox mcp` starts a [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio, allowing AI agents like Claude Code to access secrets without having them directly in the environment.

## Access model

The server resolves selected secrets on first access and caches them in memory for the session. `get_secret` returns values directly. `exec` runs a command with the allowed secrets and returns its output. Neither tool is an operating-system sandbox; configure the allowlist for the task.

## Quick setup

### 1. Configure secrets normally

```toml
# fnox.toml
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
GITHUB_TOKEN = { provider = "op", value = "GitHub/agent-token", env = "exec" }
API_KEY = { provider = "op", value = "Service/api-key", env = "exec" }
```

Authenticate to the provider before starting the MCP server; it runs non-interactively. The values above are references to existing vault items.

### 2. Configure which tools to expose

```toml
[mcp]
tools = ["get_secret", "exec"]  # default: both enabled
```

The `tools` array controls which tools are available to the agent. For example, to only allow executing commands without exposing raw secrets, set `tools = ["exec"]`. To only allow retrieving secrets directly, set `tools = ["get_secret"]`.

### Secret allowlist

By default, all profile secrets are available to the MCP server. You can restrict which secrets are visible:

```toml
[mcp]
secrets = ["GITHUB_TOKEN", "NPM_TOKEN"]  # only these are available
```

When `secrets` is set:

- `get_secret` can only retrieve listed secrets; other names return "not found"
- `exec` only injects listed secrets as environment variables
- Unlisted secrets are never resolved (no unnecessary auth prompts)

When `secrets` is omitted, all profile secrets are available (the default).

### 3. Configure your AI agent

For Claude Code, add to `.mcp.json` in your project root:

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

To use a specific profile:

```json
{
  "mcpServers": {
    "fnox": {
      "command": "fnox",
      "args": ["-P", "staging", "mcp"]
    }
  }
}
```

## Tools

### `get_secret`

Retrieves a single secret by name. The agent provides the secret name (must match a key in your `fnox.toml` secrets section) and receives the resolved value.

### `exec`

Executes a command with all secrets injected as environment variables. The agent provides a command and arguments, and receives stdout/stderr output. Note that the agent controls the command, so it could run `printenv` or `echo $SECRET` to read injected values — `exec` provides **audit visibility** (you can see what commands were run), not secret isolation.

Start the MCP client from the project directory so fnox can discover its configuration, or pass an explicit `-c` path in the server arguments.

## How it works

1. The MCP server starts in non-interactive mode (no stdin prompts)
2. On the **first tool call**, all env-injectable profile secrets (`env = true` or `env = "exec"`) are resolved in a single batch — this amortizes the cost of YubiKey taps or SSO prompts. Secrets configured with `env = false` are resolved on-demand when individually requested via `get_secret`.
3. Resolved secrets are cached in process memory for the session
4. Subsequent tool calls use the cache
5. When the agent disconnects (EOF), the process exits and all secrets are cleared from memory

## Security considerations

- Secrets live only in process memory — except for `as_file = true` secrets, which are written to ephemeral temp files for subprocess injection and deleted when the command completes
- The `exec` tool captures stdout/stderr (does not inherit stdio, which would corrupt the JSON-RPC stream) and caps output at 1 MiB to prevent unbounded memory usage
- Non-interactive mode prevents provider auth prompts from interfering with the protocol
- The `exec` tool redacts resolved secret values from stdout/stderr before returning output to the agent — commands like `printenv` or `echo $SECRET` will show `[REDACTED]` instead of the raw value. Redaction performs literal string matching and does not detect base64-encoded or otherwise transformed values. To disable (not recommended): `mcp.redact_output = false`
- With `tools = ["exec"]`, direct `get_secret` access is disabled. Output redaction reduces accidental disclosure, but an agent-controlled command can transform or transmit a value; it does not provide secret isolation
- Use `mcp.secrets` to limit which secrets the agent can access — unlisted secrets are never resolved or injected
- Disabled tools are not advertised in `tools/list` — agents only see tools they can actually call
- The MCP allowlist only controls the MCP channel — secrets injected into your shell by shell integration are still visible to any agent running there. Set the top-level `env = "exec"` default (see the [configuration reference](/reference/configuration#env)) to keep secrets out of the interactive shell entirely; they remain available through `fnox exec` and the MCP tools
