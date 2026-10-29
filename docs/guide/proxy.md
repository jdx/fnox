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

### Short-lived credentials from a lease

A rule can name a [lease](/guide/leases) instead of a secret. fnox then mints the short-lived credential itself, and neither it nor the parent credential it is minted from reaches the command. Each rule sets exactly one of `secret` and `lease`.

```toml
[secrets]
GITLAB_TOKEN = { provider = "op", value = "Forge/parent token", env = false }

[leases.forge]
type = "gitlab"
url = "https://forge.example.com"
project = "team/app"
scopes = ["api"]
duration = "1h"

[[proxy.rules]]
lease = "forge"
domain = "forge.example.com"
header = "private-token"
methods = ["POST"]
paths = ["/api/v4/projects/42/merge_requests/*/notes"]
```

The command gets a placeholder in `GITLAB_TOKEN`, the variable the lease produces; set `env` to use another name. fnox sends the minted token only in the `PRIVATE-TOKEN` header of `POST` requests to that path, with the same checks as a secret rule, and redacts it from responses.

- **Minting.** fnox resolves the lease's parent credential at startup and refuses to start if it is missing. It mints the lease the first time a matching request carries the placeholder, so a session that never uses it creates nothing. Concurrent requests share one lease. fnox mints a replacement 5 minutes before the lease expires, or after three quarters of its lifetime for a shorter lease; the old value stays redacted from responses.
- **Failures.** If minting the first lease fails, the request is refused, and a request at least 10 seconds later tries again. If a renewal fails, requests keep getting the current lease until it expires, and later requests try the renewal again. A backend's own error stays in fnox's log, because it can quote a parent credential (a `command` lease's stderr, for example). fnox removes the values it knows are parent credentials: the secrets the lease reads, and the variables a backend reads from fnox's environment. It can't know which other variables a `command` lease's script reads. Minting or revoking a lease may take 30 seconds, or a `command` lease's own `timeout` plus 5 seconds if that is longer. Encrypting a new lease's credentials for the ledger adds up to 5 more seconds; the ledger itself is written in the background, so a locked ledger doesn't hold up requests. At shutdown, fnox revokes all its leases at once, so it waits for the slowest backend, then up to 5 seconds more for the ledger to catch up. A lease it could neither revoke nor record by then is named in a warning, so you can revoke it in the service. A lease that has already expired is never injected.
- **Revocation.** When the command exits, including after fnox passes it a `SIGTERM`, `SIGHUP`, or an interrupt sent to fnox without a terminal, fnox revokes every lease it minted, for backends that support revocation. Minted leases are recorded in the [lease ledger](/guide/leases#how-caching-works), so `fnox lease list` shows them and `fnox lease revoke` can retry one that fnox couldn't revoke, for example because fnox was killed. When the default provider can encrypt, such as `age`, the ledger keeps the lease's credentials encrypted for that purpose only; backends such as GitHub App revoke a token by authenticating with it, so without them a later `fnox lease revoke` can only mark the lease revoked locally. `fnox exec` never reuses these credentials, and the proxy never reuses a lease that `fnox exec` cached, because that value has been in a command's environment.
- **Choosing a credential.** A lease that produces several variables, such as a Vault lease with an `env_map`, needs `credential = "NAME"` on the rule to pick one. So does a `command` lease, whose variables aren't known until it runs. A `command` lease may read any secret, so fnox removes every secret from the command's environment, but it can't tell which other variables the script reads: a parent credential the script takes from your shell's environment instead of a secret is still in the command's environment. `aws-sts` leases can't be used: their credentials sign requests instead of being sent in a header or query parameter.

### Secrets that aren't set yet

A rule can name a secret that has no value yet, as long as the secret is declared:

```toml
[secrets]
STRIPE_KEY = { description = "Stripe test key" }

[[proxy.rules]]
secret = "STRIPE_KEY"
domain = "api.stripe.com"
```

`fnox proxy run` starts anyway and warns that `STRIPE_KEY` isn't set. The command still gets its placeholder. A request that needs the secret is refused with `secret 'STRIPE_KEY' is not set yet`. Before refusing, fnox reads the config again and resolves the secret, at most once every few seconds. Once you set it, for example with `fnox set STRIPE_KEY` in another terminal, a matching request gets the real value without a restart. A request within 3 seconds of the last attempt is still refused, so retry after a moment. A lookup that takes longer than 15 seconds is abandoned and the request is refused; the next one tries again. A rule for a secret that isn't declared at all is still an error, so a typo in a rule doesn't go unnoticed.

An agent can also ask you for a pending secret itself: with `request_secret` enabled, the agent's `fnox mcp` relays to the proxy, which shows you a page to enter the value (see [MCP inside `fnox proxy run`](/guide/mcp#inside-fnox-proxy-run)).

Check the effective rules without resolving any secrets:

```sh
fnox proxy rules
```

## What happens

1. fnox blocks other processes from reading its memory, then resolves the secrets named in rules, the parent credentials of the leases named in rules, and anything their providers need. A secret without a value stays [pending](#secrets-that-aren-t-set-yet). A lease is minted when a request first needs it.
2. It starts a proxy on `127.0.0.1` with a temporary certificate authority and a random password for this session.
3. It starts the command with placeholders, `HTTPS_PROXY` (with the password in the URL), and the CA file in the standard environment variables.
4. For each request, fnox checks the proxy password, verifies the real server's TLS certificate, and substitutes the placeholder only if domain, method, path, and the header or query parameter all match a rule.
5. If a response echoes a real secret back, fnox replaces it with the placeholder.
6. When the command exits, fnox stops the proxy, revokes the leases it minted, and deletes the CA file. The CA's private key never leaves fnox's memory, and real values go only to the matched service, over TLS, never to the child.

The password stops other users' programs on a shared machine from using the proxy to send your credentials. Clients read it from `HTTPS_PROXY` automatically. It doesn't stop programs running as you: they can read the password from the command's environment, as they can read your fnox config (see [what it does not protect against](#what-it-does-not-protect-against)). On Linux, fnox also marks itself non-dumpable, so the command can't read fnox's memory or environment through `/proc`. On macOS, it refuses debugger attachment.

## Egress

`egress = "strict"` (the default) refuses any host without a rule. `egress = "permissive"` lets unmatched traffic through as an uninspected tunnel. Use strict for agents.

To let a few hosts through without credentials while staying strict, list them in `allow_domains`. They use the same patterns as rule domains:

```toml
[proxy]
allow_domains = ["registry.npmjs.org", "*.githubusercontent.com"]
```

### Private networks

fnox refuses to connect to addresses that aren't on the public internet: loopback, private ranges such as `10.0.0.0/8`, link-local addresses, which include cloud metadata endpoints like `169.254.169.254`, and other reserved space. This applies to rules, `allow_domains`, and permissive egress. It checks every address a name resolves to and connects only to the addresses it checked, so DNS can't redirect a request to a local service.

If a rule's API lives on your internal network, allow that network:

```toml
[proxy]
allow_private = ["10.20.0.0/16", "192.168.1.5"]
```

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

All of these send the proxy password from `HTTPS_PROXY`. curl, wget, Python, Node, and Go send it with the first request. git waits for the proxy to ask, and fnox asks on the same connection.

Not tested: Deno, Bun, the JVM, .NET, Rust programs that bundle their own roots, Node versions that ignore `NODE_USE_ENV_PROXY`, macOS, and Windows. A program that uses its own trust store may ignore the CA variables and fail the TLS handshake. A client that ignores the proxy variables connects directly, and the real server then receives the placeholder instead of the secret (confirmed with Node and the proxy variables removed).

To check a client, run it once and read the audit line:

```sh
fnox proxy run -- your-client https://api.example.com/
```

`injected=["GITHUB_TOKEN"]` means the placeholder was substituted. `injected=[]` with a `proxied request` line means the request arrived but didn't carry a placeholder in the allowed header or parameter. A `refused request` line gives the `reason`: for example, the destination has no rule, the route or method doesn't match, the address isn't public, or the client didn't send the proxy password (a client that strips credentials from proxy URLs fails this way).

Uninspected tunnels (`allow_domains` and permissive egress) aren't logged. A missing audit line is not proof that the client bypassed the proxy: it is also absent when `audit = false` and when the client rejected the proxy's CA and never sent a request. Check the client's own connection errors first, make sure `audit` is on, and run with `RUST_LOG=fnox::proxy=debug` if you need more detail.

## What it does not protect against

The proxy keeps real values out of the child's environment and network traffic. Without a sandbox, a process running as your user can ignore the proxy variables, read your fnox config and provider state, or run `fnox get` itself. For untrusted agents, use [`--sandbox`](#sandbox) or run them inside a container or VM that blocks direct network access and access to your credential stores, with the proxy as their only way out.

## Sandbox

`fnox proxy run --sandbox` runs the command in an OS sandbox, so the proxy really is its only way out:

```sh
fnox proxy run --sandbox -- node agent.js
```

Set `sandbox = true` under `[proxy]` to make it the default for a project, and pass `--no-sandbox` to turn it off for one run.

Inside the sandbox the command:

- **Can reach only the proxy.** Every other connection fails, including ones from clients that ignore `HTTPS_PROXY`. Local sockets are unreachable too: on Linux the sandbox has no `/run`, which takes the fnox daemon, D-Bus, gpg-agent, and the Docker socket with it, and `SSH_AUTH_SOCK` and `XDG_RUNTIME_DIR` are unset.
- **Cannot read fnox's files or common credential directories.** Hidden: your fnox config directory, state and data directories, every `fnox.toml` (and `fnox.local.toml`, profile files, and imports) that applies to the working directory, age key files, and `~/.ssh`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.gnupg`, `~/.password-store`, `~/.config/gcloud`, `~/.config/gh`, `~/.config/op`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, and a few similar paths. Config files that apply but don't exist yet, such as `fnox.local.toml`, can't be created by the command either, because fnox or git would read them later outside the sandbox. On Linux that makes bwrap leave an empty placeholder file, which fnox removes when the command exits.
- **Can write only the working directory and temporary files.** Everything else is read-only. `.git/hooks` and `.git/config` in the working directory are read-only as well, so the command can't plant code that git runs outside the sandbox. They are protected even if they don't exist yet; a repository that the command creates itself with `git init` is not.
- **Hides the files of inherited profiles and each provider's `key_file`,** such as an age identity, along with the other config files above. A `key_file` that isn't a literal path, such as a secret reference, is an error because the sandbox can't tell which file to hide. `sandbox_allow_read` leaves a path readable but still read-only.
- **Can read everything else.** The rest of the filesystem, including your home directory, is readable. The hidden list is not exhaustive: a credential in a location it doesn't name is readable unless you add it.

Adjust the defaults under `[proxy]`. Relative paths are resolved from the working directory and `~` is your home directory:

```toml
[proxy]
sandbox = true
sandbox_allow_write = ["~/.cache", "~/.npm"]
sandbox_deny_read = ["~/.config/some-tool"]
sandbox_allow_read = ["fnox.toml"]
```

`sandbox_allow_read` takes a path the sandbox hides by default, or a directory containing one.

### Requirements

| Platform | Needs                                                                   | How it works                                                                                                                                             |
| -------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux    | [`bwrap`](https://github.com/containers/bubblewrap) and user namespaces | The command runs in new network, PID, and IPC namespaces. A small forwarder, `fnox sandbox-bridge`, exposes the proxy on `127.0.0.1` inside the sandbox. |
| macOS    | `/usr/bin/sandbox-exec`                                                 | A generated seatbelt profile allows network access only to the proxy's loopback port.                                                                    |
| Windows  | not supported                                                           | `--sandbox` is an error.                                                                                                                                 |

fnox never falls back to running unsandboxed: if the tool is missing or the machine forbids user namespaces, `fnox proxy run` exits before it resolves any secret. Some distributions restrict unprivileged user namespaces (Ubuntu 24.04 does by default through AppArmor); allow `bwrap` there or relax the restriction.

### Limits

- The sandbox starts a new session on Linux so the command can't inject keystrokes into your terminal. Interactive programs still read and write the terminal, but Ctrl-C reaches fnox rather than the command, and fnox stops it.
- On macOS the sandbox cannot hide other processes or Mach services. `sandbox-exec` is deprecated by Apple but still works, and the Keychain stays reachable through its system service. fnox keeps `deny_inspection` on its own memory.
- The command can still do whatever your rules allow: the sandbox limits where credentials can go, not what an allowed request says.
- A kernel or sandbox vulnerability is out of scope, as is a command that tricks you into running something outside the sandbox later, such as editing a project file you then execute.

### Isolating an agent without the sandbox

If you can't use `--sandbox`, an isolated environment has to do three things:

1. **Keep your credentials out of reach.** Don't mount `~/.config/fnox`, your age keys, or provider credentials such as `~/.aws`, `~/.config/op`, or the keychain. Don't install the `fnox` binary inside it, so the agent can't run `fnox get`.
2. **Block direct network access.** Without this, a client that ignores the proxy variables can connect straight to the internet.
3. **Leave a route to the proxy.** The proxy listens on `127.0.0.1` and accepts only loopback clients, so the isolated process must share the host's loopback interface or reach it through a forwarder you run on the host. It also needs read access to the CA file named by `SSL_CERT_FILE`. Sharing loopback doesn't expose your other local services through the proxy: it refuses loopback and private destinations unless `allow_private` lists them.

The environment variables set by `fnox proxy run` have to cross the boundary too. With Docker, for example, forward them by name (`-e HTTPS_PROXY -e SSL_CERT_FILE`) and mount the CA file read-only at the same path. fnox doesn't ship an isolation wrapper, so verify your setup with the audit-line check above, and confirm that a request made without the proxy fails.

With `audit = true` (the default), fnox logs each request's method, domain, path, and which secret or lease was injected (a lease as `lease:<name>`), and each refused request with its reason. It never logs headers, bodies, or values.

## See also

- [MCP server](/guide/mcp): let an agent fetch secrets or run commands through MCP.
- [`fnox proxy` reference](/cli/proxy): `run` and `rules`.
- [Configuration reference](/reference/configuration#proxy): every proxy field.
