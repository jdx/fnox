---
description: "Inject credentials into matching HTTPS requests while passing placeholders to a command. Configure rules and understand the access model."
---

# Credential proxy

The fnox credential proxy lets a command use API credentials without receiving
their real values. The child process receives placeholders, and fnox substitutes
the real values only in approved HTTPS requests.

This is useful for AI agents and other untrusted or highly automated programs
that need to call external APIs.

## Configure rules

Proxy rules refer to secrets in the active profile:

```toml
[providers.op]
type = "1password"

[secrets]
GITHUB_TOKEN = { provider = "op", value = "GitHub/agent-token", env = false }

[proxy]
egress = "strict"
audit = true

[[proxy.rules]]
secret = "GITHUB_TOKEN"
domain = "api.github.com"
header = "authorization"
methods = ["GET", "POST", "PATCH"]
paths = ["/repos/example/**"]
placeholder = "ghp_000000000000000000000000000000000000"
```

The optional `placeholder` is useful when an SDK validates credential format.
When omitted, fnox generates a unique placeholder for the session.

Inspect the effective rules without resolving secrets:

```bash
fnox proxy rules
```

## Run a command

```bash
fnox proxy run -- codex
fnox proxy run -- claude
fnox proxy run -- node agent.js
```

fnox:

1. Resolves secrets referenced by proxy rules and any provider authentication
   secrets they depend on.
2. Starts a loopback-only HTTPS (CONNECT) proxy with an ephemeral certificate
   authority.
3. Passes placeholders and standard proxy/CA environment variables to the
   child.
4. Verifies the upstream TLS connection and substitutes a placeholder only
   when its domain, method, path, and header rule match.
5. Replaces reflected secret values in response headers and bodies with their
   placeholders.
6. Stops the proxy and deletes the public CA file when the command exits.

The CA private key and real secret values remain in fnox process memory.

## Egress modes

`egress = "strict"` is the default. Destinations without proxy rules are
rejected.

`egress = "permissive"` tunnels unmatched destinations without inspecting the
request or injecting credentials:

```toml
[proxy]
egress = "permissive"
```

Strict mode is recommended for agent workloads.

## Current limits

The proxy currently supports the following request shapes:

- Credential substitution is supported in HTTP headers.
- Plain `http://` proxy requests are rejected.
- Matched destinations must use HTTPS on port 443.
- Intercepted traffic uses HTTP/1.1.
- Request bodies must use `Content-Length`; chunked request bodies are rejected.
- Requests and responses are limited to 10 MiB.
- Domains are exact names; wildcard domains are not supported.
- Client software must honor the standard proxy and CA environment variables.

## Security model

The credential proxy prevents the child from receiving the real values through
its configured environment and proxy traffic. Rules also restrict where fnox
will inject each credential.

The proxy is not an operating-system sandbox. A determined process running
as the same user may bypass proxy environment variables, read accessible fnox
configuration or provider state, or invoke fnox directly. Run untrusted agents
in a container, VM, or other sandbox that blocks direct egress and access to
credential sources.

Request auditing logs method, domain, path, and injected secret names through
fnox tracing. It never logs request headers, bodies, or secret values.

## Next steps

- [MCP server](/guide/mcp): expose selected secrets and command execution over stdio.
- [Proxy commands](/cli/proxy): inspect rules and launch a command.
