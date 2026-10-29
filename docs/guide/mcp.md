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

The server never prompts in the terminal, so sign in to your providers (for example `op signin`) before starting the agent.

## Choose what the agent can do

```toml
[mcp]
tools = ["exec"]                         # default: ["get_secret", "exec"]
secrets = ["GITHUB_TOKEN", "NPM_TOKEN"]  # default: every secret in the profile
```

| Tool             | What the agent gets                                                                                           |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `get_secret`     | The value of one secret, by name.                                                                             |
| `exec`           | Runs a command with the secrets injected and returns its output, with secret values replaced by `[REDACTED]`. |
| `request_secret` | Asks you to enter a missing secret on a local page. The agent learns only that it was stored. Off by default. |

`secrets` limits every tool: unlisted secrets are never resolved, injected, or returned, and `request_secret` can't ask for them. Disabled tools aren't advertised to the agent at all.

## Let the agent ask for a secret

When a task needs a credential you haven't stored yet, such as an API token, the agent would normally ask you to paste it into the chat. With `request_secret`, it asks fnox instead, and you type the value into a page that fnox serves on your machine:

```toml
default_provider = "age"

[mcp]
tools = ["exec", "request_secret"]
```

1. The agent calls `request_secret` with a name, such as `TAILSCALE_AUTHKEY`, and a reason, such as where to create the key.
2. Your agent shows a link to a one-time page on `127.0.0.1`. The page shows the secret's name, the provider and config file fnox will store it in, and the agent's reason, labeled as written by the agent.
3. You enter the value and choose **Save to fnox**, or choose **Decline**.
4. fnox stores the value as `fnox set` would and tells the agent only that it was stored. From then on, `exec` sets it as an environment variable.

The value never passes through the agent's client or its model. The link accepts one submission and expires after 10 minutes. After submission, the result stays readable for 60 seconds, including after a page reload. A successful save shows **Saved**; reloading or resubmitting the page does not store another value.

fnox refuses to store the value in plain text. The secret's provider, or `default_provider` for a new secret, must encrypt values (such as `age`) or store them remotely (such as `1password`); the `plain` provider is refused. If the secret already has a value, the agent is told so and nothing is asked; it can pass `replace: true` to ask you for a new one. If the secret gets a value or a different provider while the page is open, fnox stores nothing and says so on the page.

### Client support

The link uses MCP's URL-mode elicitation, from protocol version 2025-11-25. If the agent's client doesn't support it, `request_secret` doesn't open a page. It tells the agent to ask you to run `fnox set NAME` in your own terminal, which prompts with hidden input. When the agent calls `request_secret` again, fnox loads the stored value.

If the client returns `decline` while opening the link, fnox reports the client's response without assuming you declined: a client can reject a URL or block a prompt without showing it. If you never saw the prompt, check the client's approval policy and URL restrictions. A canceled opening request, a timeout waiting for the client, and choosing **Decline** on the fnox page are reported separately. The agent is told not to reopen a rejected or canceled prompt automatically.

## Inside `fnox proxy run`

When the agent runs under the [credential proxy](/guide/proxy), for example with `fnox proxy run --sandbox -- claude`, the agent's `fnox mcp` doesn't serve the tools itself. It relays MCP to the `fnox proxy run` process, which runs outside the sandbox and holds the real values. Your `.mcp.json` doesn't change, and the relay needs no config, so it works where the sandbox hides `fnox.toml`.

The tools then work with the proxy's placeholders:

| Tool             | Inside `fnox proxy run`                                                                                                                                                                                              |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `get_secret`     | Returns the secret's placeholder, the environment variable that holds it, and the domains the proxy injects it into. Never the real value. Only secrets with a proxy rule.                                           |
| `exec`           | Not offered. It would run commands outside the sandbox; the agent runs commands inside it instead.                                                                                                                   |
| `request_secret` | Stores the value as above. With a proxy rule, hands it to the proxy, so requests that carry the placeholder get the real value, and gives the agent the placeholder. Without one, nothing in the run can use it yet. |

`request_secret` pairs with [pending rules](/guide/proxy#secrets-that-aren-t-set-yet): declare the secret and write its rule, and the agent can ask you for the value when it first needs it. The page is served by the proxy process on `127.0.0.1`, where your browser can reach it. With the default strict egress the sandboxed agent can't, so it can't fill in the form itself. If `allow_private` lists loopback and `egress` is permissive, the agent can reach the page through the proxy; keep those off when you rely on this.

`[mcp]` settings apply as usual: `tools` chooses the tools (minus `exec`) and `secrets` limits the names. The relay serves the proxy's config and profile, so `fnox mcp` refuses `-c`, or a `-P` naming another profile, under `fnox proxy run`; pass those to `fnox proxy run` instead.

## How it behaves

- On the first tool call, fnox resolves the allowed secrets in one batch, so you approve one YubiKey touch or SSO prompt per session rather than one per call. `env = false` secrets are resolved only when `get_secret` asks for them.
- Values stay in the server's memory for the session and are gone when the agent disconnects. `as_file` secrets are written to temporary files for the duration of an `exec` call.
- `exec` captures output (up to 1 MiB) instead of sharing the terminal, and times out after `exec_timeout_secs` (default 300).

## What it does and doesn't protect

`exec` without `get_secret` keeps raw values out of the agent's conversation in normal use, and every command it runs is visible to you. `request_secret` keeps a value you enter out of the conversation, but the stored value is then as reachable as any other secret: through `get_secret` if you enable it, and through `exec`. It is **not** isolation: the agent chooses the command, and a command can encode or send a value somewhere. Redaction matches literal values only, so base64 or other transformed output isn't caught. You can turn redaction off with `redact_output = false`, but there's rarely a reason to.

The `request_secret` page doesn't prove that you are the one filling it in. The agent's client receives the link, and a program running as your user could open it and submit a value of its own. Check that a secret you didn't enter yourself holds what you expect. The page also displays text the agent wrote: enter only the value for the named secret, never a password manager's master password.

Shell integration is a separate channel. If your interactive shell already has secrets loaded, an agent started from it can read them regardless of `[mcp]`. Set `env = "exec"` to keep secrets out of the shell (see [running commands](/guide/running-commands#choose-which-secrets-reach-a-command)).

For stronger isolation, give the agent API access through the [credential proxy](/guide/proxy) instead, and run it with [`fnox proxy run --sandbox`](/guide/proxy#sandbox). The MCP tools then hand out placeholders; see [inside `fnox proxy run`](#inside-fnox-proxy-run).

## See also

- [Credential proxy](/guide/proxy): the agent never sees real credentials.
- [Configuration reference](/reference/configuration#mcp-server-settings): every `[mcp]` field.
- [`fnox mcp` reference](/cli/mcp).
