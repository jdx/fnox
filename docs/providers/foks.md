# FOKS

Integrate with [FOKS](https://foks.pub) — the Federated Open Key Service — to store secrets in an end-to-end encrypted, self-hostable key-value store. Secrets are encrypted on the client; the server only ever sees ciphertext.

FOKS pairs well with fnox for teams that want their secrets manager to be open source, federated, and free of cloud-vendor lock-in. The hosted instance at [foks.app](https://foks.app) and self-hosted FOKS servers behave identically. fnox just shells out to the `foks` CLI either way.

## Quick Start

```bash
# 1. Install the foks CLI
brew install foks            # macOS / Linuxbrew
# or: curl -fsSL https://pkgs.foks.pub/install.sh | sh && apt-get install foks  # Debian/Ubuntu

# 2. Start the agent and sign up (or log in)
foks ctl start
foks signup

# 3. Configure the FOKS provider
cat >> fnox.toml << 'EOF'
[providers]
foks = { type = "foks", prefix = "/fnox/" }

[secrets]
DATABASE_URL = { provider = "foks", value = "DATABASE_URL" }
EOF

# 4. Store a secret and read it back
fnox set DATABASE_URL "postgres://..." --provider foks
fnox get DATABASE_URL
```

## Prerequisites

- The [`foks` CLI](https://foks.pub) on your `PATH`
- A running FOKS agent (`foks ctl start`)
- A FOKS account, either on the [hosted service](https://foks.app) or your own server

## Installation

```bash
# macOS (Homebrew)
brew install foks

# Debian / Ubuntu
curl -fsSL https://pkgs.foks.pub/install.sh | sh
apt-get install foks

# Fedora
curl -fsSL https://pkgs.foks.pub/install.sh | sh
dnf install foks

# Arch Linux (AUR)
yay -Sy go-foks

# Windows
winget install foks

# Static binary (any platform)
curl -fsSL https://pkgs.foks.pub/install-static.sh | sh
```

See [foks.pub](https://foks.pub) for the most up-to-date instructions.

## Setup

### 1. Start the agent

The `foks` CLI talks to a long-running agent that holds your keys in memory (similar to `ssh-agent`). Start it once per machine; it persists across logins via launchd / systemd / the Windows Registry.

```bash
foks ctl start
```

### 2. Sign up or log in

```bash
foks signup    # new user
foks login     # existing user, new device
```

### 3. (Optional) Create a team for shared secrets

If you want to share secrets with teammates, create a FOKS team:

```bash
foks team create my-team
foks team add my-team alice
```

Each team has its own KV namespace.

### 4. Configure the provider

```toml
[providers]
foks = { type = "foks", prefix = "/fnox/" }
```

**Configuration options** (all optional):

- `prefix` — Path prefix prepended to every key (must be absolute, e.g. `/fnox/` or `/apps/myapp/`). FOKS rejects relative paths; if you forget the leading `/`, the provider adds it for you.
- `team` — A FOKS team name. When set, fnox passes `--team <name>` to every `foks kv` invocation, so secrets read and write to that team's namespace instead of your personal one.
- `home` — A custom FOKS home directory, passed through as `--home`. Falls back to `FNOX_FOKS_HOME` / `FOKS_HOME` if not set.
- `host` — The FOKS server hostname (e.g. `foks.app` or your self-hosted server). Required for non-interactive bot-token auth (see [CI/CD](#cicd)). Falls back to `FNOX_FOKS_HOST` / `FOKS_HOST`.
- `bot_token` — A FOKS bot token for non-interactive auth (CI). Almost always you want to leave this unset and supply it via the `FOKS_BOT_TOKEN` env var instead, so it isn't checked into your config. Also accepts `FNOX_FOKS_BOT_TOKEN`.

## Referencing Secrets

```toml
[secrets]
DATABASE_URL = { provider = "foks", value = "DATABASE_URL" }
API_KEY      = { provider = "foks", value = "API_KEY" }
```

The `value` is the key path within the FOKS KV store, joined with the provider's `prefix`. With `prefix = "/fnox/"`, `value = "DATABASE_URL"` resolves to `foks kv get /fnox/DATABASE_URL`.

## Usage

```bash
# Store a secret (FOKS encrypts it client-side before upload)
fnox set DATABASE_URL "postgres://..." --provider foks

# Fetch it
fnox get DATABASE_URL

# Run a command with secrets injected as env vars
fnox exec -- npm start
```

## Personal vs Team Secrets

Use named provider instances to mix personal and team-scoped secrets in the same config:

```toml
[providers]
me  = { type = "foks", prefix = "/fnox/" }
ops = { type = "foks", prefix = "/fnox/", team = "ops" }

[secrets]
PERSONAL_TOKEN = { provider = "me",  value = "github-token" }
DATABASE_URL   = { provider = "ops", value = "db/primary" }
DEPLOY_KEY     = { provider = "ops", value = "deploy/key" }
```

`PERSONAL_TOKEN` is read from your personal namespace; the rest are read from the `ops` team's namespace and stay accessible to teammates.

## CI/CD

For non-interactive environments, configure the provider with a `host` and let fnox handle authentication via a FOKS bot token. On the first auth failure, the provider runs `foks bot use --host <host>` with the token from the `FOKS_BOT_TOKEN` env var, then transparently retries.

Setup:

1. Create a [bot token](https://docs.foks.pub) for the user or team the runner should act as.
2. Add the token to your CI provider's secret store as `FOKS_BOT_TOKEN`.
3. Set `host` in the provider config (or `FOKS_HOST` env var).

```toml
# fnox.toml
[providers]
foks = { type = "foks", prefix = "/fnox/", team = "ops", host = "foks.app" }

[secrets]
DATABASE_URL = { provider = "foks", value = "DATABASE_URL" }
```

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      FOKS_BOT_TOKEN: ${{ secrets.FOKS_BOT_TOKEN }}
    steps:
      - uses: actions/checkout@v4
      - run: brew install foks
      - run: foks ctl start
      - run: fnox exec -- ./deploy.sh
```

fnox runs `foks bot use` the first time the agent reports it's not authenticated, then retries the failed `kv` call once.

If you'd rather keep `host` out of `fnox.toml`, set it via `FOKS_HOST` in the workflow env. Likewise, `bot_token` can live in the config (encrypted with a bootstrap provider like `age`) instead of the env var, but the env var is usually simpler.

## Pros

- ✅ End-to-end encrypted — the FOKS server never sees plaintext
- ✅ Open source and self-hostable
- ✅ Federated: a self-hosted FOKS server interoperates with the hosted service
- ✅ Teams have first-class shared namespaces
- ✅ Hierarchical KV paths and multiple devices per identity

## Cons

- ❌ Newer / smaller ecosystem than Vault, AWS Secrets Manager, etc.
- ❌ Requires the `foks` agent to be running locally
- ❌ CI integration requires a bot-token bootstrap step

## Troubleshooting

### "could not connect to the FOKS agent"

Start the agent and try again:

```bash
foks ctl start
foks ctl status
```

### "no logged-in user" / "not logged in"

Sign up or log in:

```bash
foks signup    # new account
foks login     # existing account
```

### Secret not found

List the keys to confirm the path is what you expect:

```bash
foks kv ls /
foks kv ls /fnox/   # if you set prefix = "/fnox/"
```

If you set a `team` in your provider config, scope the listing to the team:

```bash
foks kv ls --team my-team /
```

## Next Steps

- [HashiCorp Vault](/providers/vault) — Closest comparable self-hosted alternative
- [password-store](/providers/password-store) — GPG-based local alternative
- [Real-World Example](/guide/real-world-example) — Complete setup walkthrough
