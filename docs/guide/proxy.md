---
description: "Let an AI agent or other untrusted program call APIs without seeing the real credentials: fnox gives it placeholders and injects the real values into approved HTTPS requests."
---

# Credential proxy

`fnox proxy run` starts a command with **placeholder** credentials and a local HTTPS proxy. When the command sends a request that matches a rule you wrote, fnox swaps the placeholder for the real value on the way out. The command never holds the real secret.

It's built for AI coding agents and other automation that needs API access but shouldn't be trusted with the keys.

```sh
fnox proxy run -- claude
fnox proxy run -- codex
fnox proxy run -- node agent.js
```

## Write rules

Each rule says which secret may be sent where:

```toml
[providers.op]
type = "1password"

[secrets]
GITHUB_TOKEN = { provider = "op", value = "GitHub/agent-token", env = false }

[proxy]
egress = "strict" # default: block hosts that have no rule

[[proxy.rules]]
secret = "GITHUB_TOKEN"
domain = "api.github.com"
header = "authorization"
methods = ["GET", "POST", "PATCH"]
paths = ["/repos/example/**"]
```

With this config, the agent sees a placeholder in `GITHUB_TOKEN`. fnox substitutes the real token only into the `Authorization` header of `GET`, `POST`, or `PATCH` requests to `https://api.github.com/repos/example/...`. Requests to hosts without a rule are refused.

Set `placeholder = "ghp_000…"` on a rule if an SDK checks the credential's format; otherwise fnox generates one per session.

Check the effective rules without resolving any secrets:

```sh
fnox proxy rules
```

## What happens

1. fnox resolves the secrets named in rules, plus anything their providers need.
2. It starts a proxy on `127.0.0.1` with a temporary certificate authority.
3. It starts the command with placeholders, `HTTPS_PROXY`, and the CA file in the standard environment variables.
4. For each request, fnox verifies the real server's TLS certificate and substitutes the placeholder only if domain, method, path, and header all match a rule.
5. If a response echoes a real secret back, fnox replaces it with the placeholder.
6. When the command exits, fnox stops the proxy and deletes the CA file. The CA's private key and the real values never leave fnox's memory.

## Egress

`egress = "strict"` (the default) refuses any host without a rule. `egress = "permissive"` lets unmatched traffic through as an uninspected tunnel. Use strict for agents.

## Limits

- Substitution happens in HTTP headers only.
- Matched hosts must use HTTPS on port 443. Plain `http://` requests are refused.
- Intercepted traffic uses HTTP/1.1. Request bodies need a `Content-Length` (no chunked uploads). Requests and responses are capped at 10 MiB.
- Domains are exact; there are no wildcards.
- The program must honor the standard proxy and CA environment variables.

## What it does not protect against

The proxy keeps real values out of the child's environment and network traffic. It is not a sandbox: a process running as your user can ignore the proxy variables, read your fnox config and provider state, or run `fnox get` itself. For untrusted agents, run them inside a container or VM that blocks direct network access and access to your credential stores, with the proxy as their only way out.

With `audit = true` (the default), fnox logs each request's method, domain, path, and which secret was injected. It never logs headers, bodies, or values.

## See also

- [MCP server](/guide/mcp): let an agent fetch secrets or run commands through MCP.
- [`fnox proxy` reference](/cli/proxy): `run` and `rules`.
- [Configuration reference](/reference/configuration#proxy): every proxy field.
