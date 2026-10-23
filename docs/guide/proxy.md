---
description: "Let an AI agent or other untrusted program call APIs without seeing the real credentials: fnox gives it placeholders and injects the real values into approved HTTPS requests."
---

# Credential proxy

`fnox proxy run` starts a command with **placeholder** credentials and a local HTTPS proxy. When the command sends a request that matches a rule you wrote, fnox swaps the placeholder for the real value on the way out. The command's environment holds only placeholders. (This does not stop other access by the same user; see [what it does not protect against](#what-it-does-not-protect-against).)

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

### Secrets in the query string

Some APIs take the key as a query parameter. Use `query` instead of `header` to name the parameter:

```toml
[[proxy.rules]]
secret = "MAPS_KEY"
domain = "maps.example.com"
query = "key"
methods = ["GET"]
```

A request to `https://maps.example.com/geocode?q=Paris&key=<placeholder>` is sent upstream with the real value in `key`, percent-encoded. A rule substitutes in one place: set `query` or `header`, not both. The placeholder is refused if it shows up anywhere else, such as another parameter, the path, or a header, or if it appears more than once.

Query strings often end up in server logs and in `Location` headers, so prefer a header when the API accepts one. fnox redacts both the raw and the percent-encoded form of a query secret if a response echoes it.

### Subdomains

A leading `*.` matches exactly one subdomain label:

```toml
[[proxy.rules]]
secret = "S3_TOKEN"
domain = "*.s3.example.com"
```

This matches `bucket.s3.example.com`. It does not match `s3.example.com` itself or `a.b.s3.example.com`. `*` is allowed only as the first label, and the rest must have at least two labels, so `*.com` and `api.*` are rejected. The real value is sent to any host the pattern matches, so use a wildcard only for domains you control or fully trust.

Check the effective rules without resolving any secrets:

```sh
fnox proxy rules
```

## What happens

1. fnox resolves the secrets named in rules, plus anything their providers need.
2. It starts a proxy on `127.0.0.1` with a temporary certificate authority.
3. It starts the command with placeholders, `HTTPS_PROXY`, and the CA file in the standard environment variables.
4. For each request, fnox verifies the real server's TLS certificate and substitutes the placeholder only if domain, method, path, and the header or query parameter all match a rule.
5. If a response echoes a real secret back, fnox replaces it with the placeholder.
6. When the command exits, fnox stops the proxy and deletes the CA file. The CA's private key never leaves fnox's memory, and real values go only to the matched service, over TLS, never to the child.

## Egress

`egress = "strict"` (the default) refuses any host without a rule. `egress = "permissive"` lets unmatched traffic through as an uninspected tunnel. Use strict for agents.

## Limits

- Substitution happens in one HTTP header or one query parameter per rule. Request bodies and the URL path are never rewritten.
- Matched hosts must use HTTPS on port 443. Plain `http://` requests are refused.
- Intercepted traffic uses HTTP/1.1. Request bodies need a `Content-Length` (no chunked uploads). Requests and responses are capped at 10 MiB.
- Domains are exact, except for a leading `*.` that matches one subdomain label.
- The program must honor the standard proxy and CA environment variables.

## Client compatibility

The proxy only sees traffic from clients that honor the standard proxy and CA environment variables. fnox sets `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NODE_USE_ENV_PROXY`, and the CA variables `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `DENO_CERT`.

Tested on Linux (x86-64) against a real HTTPS API, with a placeholder in a header. In each case the audit log showed the secret injected:

| Client                          | Result                                      |
| ------------------------------- | ------------------------------------------- |
| curl 8.5.0                      | Works                                       |
| wget 1.21.4                     | Works                                       |
| Python 3.12.3 (`urllib`)        | Works                                       |
| Node 24.22.1 (`fetch`, `https`) | Works                                       |
| Go 1.27.2 (`net/http`)          | Works                                       |
| git 2.53.0                      | Routed through the proxy and trusted its CA |

Not tested: Deno, Bun, the JVM, .NET, Rust programs that bundle their own roots, Node versions that ignore `NODE_USE_ENV_PROXY`, macOS, and Windows. A program that uses its own trust store may ignore the CA variables and fail the TLS handshake. A client that ignores the proxy variables connects directly, and the real server then receives the placeholder instead of the secret (confirmed with Node and the proxy variables removed).

To check a client, run it once and read the audit line:

```sh
fnox proxy run -- your-client https://api.example.com/
```

`injected=["GITHUB_TOKEN"]` means the placeholder was substituted. `injected=[]` with a `proxied request` line means the request arrived but didn't carry a placeholder in the allowed header or parameter. A missing audit line is not proof that the client bypassed the proxy: the line is only written for requests that pass the rules, so it is also absent when `audit = false`, when the request was refused (the client sees a 403), and when the client rejected the proxy's CA and never sent a request. Check the client's own connection errors first, make sure `audit` is on, and run with `RUST_LOG=fnox::proxy=debug` if you need more detail.

## What it does not protect against

The proxy keeps real values out of the child's environment and network traffic. It is not a sandbox: a process running as your user can ignore the proxy variables, read your fnox config and provider state, or run `fnox get` itself. For untrusted agents, run them inside a container or VM that blocks direct network access and access to your credential stores, with the proxy as their only way out.

### Isolating an agent

An isolated environment has to do three things:

1. **Keep your credentials out of reach.** Don't mount `~/.config/fnox`, your age keys, or provider credentials such as `~/.aws`, `~/.config/op`, or the keychain. Don't install the `fnox` binary inside it, so the agent can't run `fnox get`.
2. **Block direct network access.** Without this, a client that ignores the proxy variables can connect straight to the internet.
3. **Leave a route to the proxy.** The proxy listens on `127.0.0.1` and accepts only loopback clients, so the isolated process must share the host's loopback interface or reach it through a forwarder you run on the host. It also needs read access to the CA file named by `SSL_CERT_FILE`.

The environment variables set by `fnox proxy run` have to cross the boundary too. With Docker, for example, forward them by name (`-e HTTPS_PROXY -e SSL_CERT_FILE`) and mount the CA file read-only at the same path. fnox doesn't ship an isolation wrapper, so verify your setup with the audit-line check above, and confirm that a request made without the proxy fails.

With `audit = true` (the default), fnox logs each request's method, domain, path, and which secret was injected. It never logs headers, bodies, or values.

## See also

- [MCP server](/guide/mcp): let an agent fetch secrets or run commands through MCP.
- [`fnox proxy` reference](/cli/proxy): `run` and `rules`.
- [Configuration reference](/reference/configuration#proxy): every proxy field.
