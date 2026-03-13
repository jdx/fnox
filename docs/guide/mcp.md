# MCP Server

`fnox mcp` starts a [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio, allowing AI agents like Claude Code to access secrets without having them directly in the environment.

## Why?

When you give an AI agent `GITHUB_TOKEN` as an environment variable, it can use that token however it wants. The MCP server acts as a **session-scoped secret broker** — secrets are resolved on first access and cached in memory for the session.

## Quick Setup

### 1. Configure secrets normally

```toml
# fnox.toml
[providers]
age = { type = "age" }

[secrets]
GITHUB_TOKEN = { provider = "age", value = "AGE-SECRET-KEY-..." }
API_KEY = { provider = "age", value = "AGE-SECRET-KEY-..." }
```

### 2. (Optional) Configure which tools to expose

```toml
[mcp]
tools = ["get_secret", "exec"]  # default: both enabled
```

The `tools` array controls which tools are available to the agent. For example, to only allow executing commands without exposing raw secrets, set `tools = ["exec"]`. To only allow retrieving secrets directly, set `tools = ["get_secret"]`.

### 3. Configure your AI agent

For Claude Code, add to `.claude/settings.json`:

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

## How It Works

1. The MCP server starts in non-interactive mode (no stdin prompts)
2. On the **first tool call**, all `env = true` profile secrets are resolved in a single batch — this amortizes the cost of yubikey taps or SSO prompts. Secrets configured with `env = false` are resolved on-demand when individually requested via `get_secret`.
3. Resolved secrets are cached in process memory for the session
4. Subsequent tool calls use the cache
5. When the agent disconnects (EOF), the process exits and all secrets are cleared from memory

## Security Considerations

- Secrets live only in process memory — except for `as_file = true` secrets, which are written to ephemeral temp files for subprocess injection and deleted when the command completes
- The `exec` tool captures stdout/stderr (does not inherit stdio, which would corrupt the JSON-RPC stream) and caps output at 1 MiB to prevent unbounded memory usage
- Non-interactive mode prevents provider auth prompts from interfering with the protocol
- The `exec` tool redacts resolved secret values from stdout/stderr before returning output to the agent — commands like `printenv` or `echo $SECRET` will show `[REDACTED]` instead of the raw value. Redaction performs literal string matching and does not detect base64-encoded or otherwise transformed values. To disable (not recommended): `mcp.redact_output = false`
- With `tools = ["exec"]` and redaction enabled (default), agents cannot retrieve raw secret values through either `get_secret` or subprocess output
- Disabled tools are not advertised in `tools/list` — agents only see tools they can actually call
