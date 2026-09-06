---
description: "Read Bitwarden vault items with bw or rbw. Configure authentication, item fields, and an optional local cache."
---

# Bitwarden

Integrate with Bitwarden (or self-hosted Vaultwarden) to retrieve secrets from your vault.

## Quick start

Install the [Bitwarden CLI](https://bitwarden.com/help/cli/), sign in, and unlock the vault:

```sh
bw login
export BW_SESSION="$(bw unlock --raw)"
```

Create a login item named `Database` in the Bitwarden app, or use an existing item. Add its reference to `fnox.toml`:

```toml
[providers.bitwarden]
type = "bitwarden"

[secrets]
DATABASE_PASSWORD = { provider = "bitwarden", value = "Database/password" }
```

```sh
fnox provider test bitwarden
fnox exec -- npm start
```

This is the password manager integration. For Bitwarden Secrets Manager and machine-account tokens, use [`bitwarden-sm`](/providers/bitwarden-sm).

## Prerequisites

- [Bitwarden account](https://bitwarden.com) (or self-hosted Vaultwarden)
- [Bitwarden CLI](https://bitwarden.com/help/cli/) (`bw`)

## Installation

Install the Bitwarden CLI:

```bash
# macOS
brew install bitwarden-cli

# Linux
npm install -g @bitwarden/cli

# Windows
choco install bitwarden-cli
```

## Setup

### 1. Login to Bitwarden

```bash
# Cloud Bitwarden
bw login

# Self-hosted Vaultwarden
bw config server https://vault.example.com
bw login
```

### 2. Unlock and get session token

```bash
# Unlock vault
export BW_SESSION=$(bw unlock --raw)

# Or if already unlocked
bw unlock
# Copy the session token from output
```

### 3. Store session token (bootstrap)

Optionally, store the session encrypted for easy bootstrap:

```bash
# Store token encrypted with age
bw unlock --raw | fnox set BW_SESSION --provider age

# Next time, bootstrap from fnox:
export BW_SESSION=$(fnox get BW_SESSION)
```

### 4. Configure Bitwarden provider

```toml
[providers]
bitwarden = { type = "bitwarden", collection = "my-collection-id", organization_id = "my-org-id" }  # both optional
```

## Adding secrets to Bitwarden

### Via Bitwarden web Vault

1. Go to [vault.bitwarden.com](https://vault.bitwarden.com)
2. Click + Add Item
3. Choose type (Login, Card, Identity, Secure Note)
4. Fill in details
5. Save

### Via Bitwarden CLI

`bw create item` accepts an encoded JSON item, rather than `--name` and `--password` flags. Follow the [Bitwarden CLI creation instructions](https://bitwarden.com/help/cli/#create) for the current item schema.

## Referencing secrets

Add references to `fnox.toml`:

```toml
[secrets]
DATABASE_PASSWORD = { provider = "bitwarden", value = "Database" }  # Item name (fetches 'password' field)
DB_USERNAME = { provider = "bitwarden", value = "Database/username" }  # Specific field
API_KEY = { provider = "bitwarden", value = "API Key" }
```

## Reference formats

### 1. Item name (gets password field)

```toml
[secrets]
MY_SECRET = { provider = "bitwarden", value = "My Item" }  # → Gets the 'password' field
```

### 2. Item name + field

```toml
[secrets]
USERNAME = { provider = "bitwarden", value = "Database/username" }
PASSWORD = { provider = "bitwarden", value = "Database/password" }
TOTP = { provider = "bitwarden", value = "Database/totp" }
API_KEY = { provider = "bitwarden", value = "Database/API Key" }
```

Supported standard fields are `username`, `password`, `notes`, `uri` (or
`url`), and `totp`. Any other field name is resolved as a custom field. Custom
field names may contain `/` and are case-sensitive when using the default `bw`
backend.

## Usage

```bash
# Unlock Bitwarden (once per session)
export BW_SESSION=$(bw unlock --raw)
# Or bootstrap: export BW_SESSION=$(fnox get BW_SESSION)

# Get secrets
fnox get DATABASE_PASSWORD

# Run commands
fnox exec -- npm start
```

## Multi-environment example

```toml
# Bootstrap session token (encrypted in git)
[providers]
age = { type = "age", recipients = ["age1..."] }
bitwarden = { type = "bitwarden" }

[secrets]
BW_SESSION = { provider = "age", value = "encrypted-session..." }
DATABASE_URL = { provider = "bitwarden", value = "Dev Database" }

# Production: Different Bitwarden organization
[profiles.production.providers]
bitwarden = { type = "bitwarden", organization_id = "prod-org-id" }

[profiles.production.secrets]
DATABASE_URL = { provider = "bitwarden", value = "Prod Database" }
```

## Multi-profile example

`bw` supports multiple accounts, as per the [official documentation](https://bitwarden.com/help/cli/#log-in-to-multiple-accounts).
fnox can access secrets in a specific profile by supplying an optional `profile` attribute to the provider:

```toml
default_provider = "bitwarden"

[providers.bitwarden]
type = "bitwarden"
profile = "Business"

[providers.bitwarden-perso]
type = "bitwarden"
profile = "Personal"
```

## `rbw` support

[`rbw`](https://github.com/doy/rbw) is a stateful alternative to `bw`.

fnox supports rbw via an experimental backend.

```toml
default_provider = "bitwarden"

[providers.bitwarden]
type = "bitwarden"
backend = "rbw"
auth_command = "rbw unlock"
```

The `auth_command` override ensures fnox prompts with `rbw unlock` instead of the default `bw login` when authentication fails.

NB: you must have set up the `rbw` CLI independently from fnox using `rbw login`.

## Self-hosted Vaultwarden

Vaultwarden is a lightweight, open-source Bitwarden-compatible server:

```bash
# Configure Bitwarden CLI to use Vaultwarden
bw config server https://vault.example.com

# Login
bw login

# Unlock
export BW_SESSION=$(bw unlock --raw)

# Use normally with fnox
fnox get DATABASE_PASSWORD
```

## CI/CD example

### GitHub Actions

```yaml
name: Test
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v4

      - name: Setup Bitwarden session
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
        run: |
          # Bootstrap session from fnox (if stored)
          export BW_SESSION=$(fnox get BW_SESSION)

      - name: Run tests
        env:
          BW_SESSION: ${{ secrets.BW_SESSION }} # Or set directly from GitHub Secrets
        run: |
          fnox exec -- npm test
```

## Session token management

The `BW_SESSION` value represents an unlocked vault session. If the session is no longer valid, unlock again and update the environment variable.

### Option 1: unlock each time

```bash
#!/bin/bash
export BW_SESSION=$(bw unlock --raw)
fnox exec -- npm start
```

### Option 2: store encrypted (bootstrap)

```bash
# Store once
bw unlock --raw | fnox set BW_SESSION --provider age

# Use repeatedly
export BW_SESSION=$(fnox get BW_SESSION)
fnox exec -- npm start
```

::: tip Refresh an unavailable session
If the vault is locked or the session is no longer usable, unlock it again:

```bash
export BW_SESSION=$(bw unlock --raw)
```

:::

## Collections and organizations

Filter secrets by collection or organization:

```toml
[providers]
bitwarden = { type = "bitwarden", collection = "abc123-collection-id", organization_id = "org-id" }
```

NB: This feature is supported only by the `bw` backend.

Get collection ID:

```bash
bw list collections | jq '.[] | {name, id}'
```

Get organization ID:

```bash
bw list organizations | jq '.[] | {name, id}'
```

## Testing with Vaultwarden

For local development without a Bitwarden account:

```bash
# Start local vaultwarden server
source ./test/setup-bitwarden-test.sh

# Follow on-screen instructions:
# Create account at https://localhost:8080 (accept self-signed certificate)
# Login: export NODE_TLS_REJECT_UNAUTHORIZED=0 && bw login
# Unlock: export BW_SESSION=$(bw unlock --raw)

# Run tests
mise run test:bats -- test/bitwarden.bats
```

See the [local testing guide](https://github.com/jdx/fnox/blob/main/test/BITWARDEN_TESTING.md) for details.

## Usage notes

The `bw` backend needs an unlocked vault session. A self-hosted Vaultwarden server uses the same reference formats. For machine credentials in Bitwarden Secrets Manager, use the separate `bitwarden-sm` provider.

## Troubleshooting

### "You are not logged in"

```bash
bw login
```

### "Vault is locked"

```bash
export BW_SESSION=$(bw unlock --raw)
```

### "Item not found"

Check the item exists:

```bash
bw list items | jq '.[] | {name, id}'
```

### "Session token expired"

Re-unlock:

```bash
export BW_SESSION=$(bw unlock --raw)
```

## Next steps

- [1Password](/providers/1password) - Commercial alternative
- [OS Keychain](/providers/keychain) - Local alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
