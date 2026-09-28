---
description: "Connect a 1Password vault, create a personal encrypted cache with age, and use it from your shell."
---

# Connect a vault and cache locally

Keep secrets in 1Password, commit their references in `fnox.toml`, and use `fnox sync` to create an encrypted personal cache. Daily reads then use your local age key without contacting 1Password. This is [the golden path](/guide/what-is-fnox#the-golden-path) for teams with an existing vault.

The same recipe works with any remote provider — swap 1Password for [AWS Secrets Manager](/providers/aws-sm), [Bitwarden](/providers/bitwarden), [Doppler](/providers/doppler), or any other [remote provider](/providers/overview).

## Prerequisites

- [fnox installed](/guide/installation)
- The [1Password CLI](https://developer.1password.com/docs/cli/) installed and signed in (`op signin`)
- `age` installed (`brew install age` / `apt install age`)

## Step 1: one-time machine setup

Create a personal age key and a machine-wide `sync-age` provider. You do this once per machine, then reuse it in every project:

```bash
# Generate your personal age key
mkdir -p ~/.config/fnox
age-keygen -o ~/.config/fnox/age.txt

# Add the machine-wide provider, then replace its age1... placeholder
# with the "public key:" line from ~/.config/fnox/age.txt
fnox provider add sync-age age --global
"${EDITOR:-vi}" "${FNOX_CONFIG_DIR:-$HOME/.config/fnox}/config.toml"
```

Point the provider at your key file so decryption works without any environment setup:

```toml
# ~/.config/fnox/config.toml
[providers.sync-age]
type = "age"
recipients = ["age1..."] # your public key
key_file = "~/.config/fnox/age.txt"
```

::: tip Harden it with hardware
Instead of a key file on disk, the age key can live in [Apple's Secure Enclave (Touch ID)](/guide/sync#apple-secure-enclave-touch-id), a [YubiKey](/guide/sync#yubikey), or a [TPM or FIDO2 token](/guide/sync#tpm-and-fido2). Only this step changes — everything below stays the same.
:::

## Step 2: put secrets in 1Password

The vault is the single source of truth. Use existing items, or create them:

```bash
op item create --category=login --vault=Engineering --title=Database \
  'url=postgresql://db.example.com/myapp'
op item create --category=login --vault=Engineering --title=Stripe \
  'secret-key=sk_live_...'
```

## Step 3: commit references in fnox.TOML

In the project, reference the 1Password items — no secret material goes into git:

```bash
cd my-api
fnox init --skip-wizard
```

```toml
# fnox.toml (committed)
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
STRIPE_KEY = { provider = "op", value = "Stripe/secret-key" }
```

Make sure the local cache never gets committed:

```bash
echo "fnox.local.toml" >> .gitignore
git add fnox.toml .gitignore
git commit -m "chore: add fnox config"
```

## Step 4: sync

Pull every secret from 1Password once and cache it locally, re-encrypted to your personal age key:

```bash
fnox sync --provider sync-age --local-file
```

This writes the encrypted values into the gitignored `fnox.local.toml`. From now on fnox decrypts locally instead of calling 1Password — see [Syncing Secrets Locally](/guide/sync) for exactly what this looks like on disk.

## Step 5: enable shell integration

```bash
# Add to your shell profile
eval "$(fnox activate zsh)"
```

For other shells and startup file locations, see [shell integration](/guide/shell-integration). Entering the project now loads secrets from the local cache:

```bash
~/projects $ cd my-api
fnox: +2 DATABASE_URL, STRIPE_KEY
~/projects/my-api $
```

## Keep the cache current

The cache does not refresh automatically. After a secret changes in 1Password, re-sync:

```bash
fnox sync --provider sync-age --local-file --force
```

**Onboard a teammate:** grant vault access, then have them complete Step 1 on their machine, clone the repo, and run Step 4. Their cache is encrypted to their own key — nothing is shared except the vault.

**Add a secret:** Add the item to 1Password, add its reference to `fnox.toml`, commit, and everyone re-syncs.

## What about CI?

In CI, authenticate to the vault directly. Install fnox and the 1Password CLI before this workflow step:

```yaml
# GitHub Actions
- name: Run tests
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
  run: fnox exec -- npm test
```

The committed `fnox.toml` references resolve straight from 1Password using the [service account token](https://developer.1password.com/docs/service-accounts/). Alternatively, keep a separate set of [age-encrypted secrets in git](/providers/age) for CI.

## Next steps

- [Syncing Secrets Locally](/guide/sync) - Everything `fnox sync` can do, including hardware-backed keys
- [Real-World Setup](/guide/real-world-example) - An alternative workflow with encrypted secrets in git
- [Profiles](/guide/profiles) - Different secrets for dev, staging, and production
- [Credential Leases](/guide/leases) - Short-lived credentials from long-lived masters
