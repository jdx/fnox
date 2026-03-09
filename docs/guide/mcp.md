# MCP Server

`fnox mcp` starts a [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio, allowing AI agents like Claude Code to access secrets without having them directly in the environment.

## Why?

When you give an AI agent `GITHUB_TOKEN` as an environment variable, it can use that token however it wants. The MCP server acts as a **session-scoped secret broker** — secrets are resolved on first access, cached in memory for the session, and never persisted to disk.

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

Set `tools = ["exec"]` to only allow running commands (agent never sees raw secrets). Set `tools = ["get_secret"]` to only allow reading secrets directly.

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

Executes a command with all secrets injected as environment variables. The agent provides a command and arguments, and receives stdout/stderr output. The agent never sees the raw secret values — they're only present in the subprocess environment.

## How It Works

1. The MCP server starts in non-interactive mode (no stdin prompts)
2. On the **first tool call**, all profile secrets are resolved in a single batch — this amortizes the cost of yubikey taps or SSO prompts
3. Resolved secrets are cached in process memory for the session
4. Subsequent tool calls use the cache
5. When the agent disconnects (EOF), the process exits and all secrets are cleared from memory

## Security Considerations

- Secrets live only in process memory — never written to disk
- The `exec` tool captures stdout/stderr (does not inherit stdio, which would corrupt the JSON-RPC stream)
- Non-interactive mode prevents provider auth prompts from interfering with the protocol
- Use `tools = ["exec"]` to prevent agents from reading raw secret values
