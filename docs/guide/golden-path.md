# Golden Path Setup

A complete, zero-to-working walkthrough of [the golden path](/guide/what-is-fnox#the-golden-path): secrets live in 1Password, `fnox.toml` commits only references to them, and `fnox sync` caches everything locally under a personal age key so day-to-day loads are instant and offline.

The same recipe works with any remote provider — swap 1Password for [AWS Secrets Manager](/providers/aws-sm), [Bitwarden](/providers/bitwarden), [Doppler](/providers/doppler), or any other [remote provider](/providers/overview).

## Prerequisites

- [fnox installed](/guide/installation)
- The [1Password CLI](https://developer.1password.com/docs/cli/) installed and signed in (`op signin`)
- `age` installed (`brew install age` / `apt install age`)

## Step 1: One-Time Machine Setup

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

## Step 2: Put Secrets in 1Password

The vault is the single source of truth. Use existing items, or create them:

```bash
op item create --category=login --vault=Engineering --title=Database \
  'url=postgresql://db.example.com/myapp'
op item create --category=login --vault=Engineering --title=Stripe \
  'secret-key=sk_live_...'
```

## Step 3: Commit References in fnox.toml

In the project, reference the 1Password items — no secret material goes into git:

```bash
cd my-api
fnox init
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
git commit -m "add fnox config"
```

## Step 4: Sync

Pull every secret from 1Password once and cache it locally, re-encrypted to your personal age key:

```bash
fnox sync --provider sync-age --local-file
```

This writes the encrypted values into the gitignored `fnox.local.toml`. From now on fnox decrypts locally instead of calling 1Password — see [Syncing Secrets Locally](/guide/sync) for exactly what this looks like on disk.

## Step 5: Enable Shell Integration

```bash
# Add to your shell profile
eval "$(fnox activate zsh)"  # or bash, fish
```

Entering the project now loads secrets instantly, offline, with no 1Password calls:

```bash
~/projects $ cd my-api
fnox: +2 DATABASE_URL, STRIPE_KEY
~/projects/my-api $
```

## Day-to-Day

**A secret changed in 1Password?** Re-sync:

```bash
fnox sync --provider sync-age --local-file --force
```

**A teammate joins?** They do Step 1 once on their machine, clone the repo, and run Step 4. Their cache is encrypted to their own key — nothing is shared except the vault.

**A new secret?** Add the item to 1Password, add its reference to `fnox.toml`, commit, and everyone re-syncs.

## What About CI?

Don't sync in CI — the cache is a per-developer convenience, and a synced key sitting in CI defeats its purpose. Instead, let CI authenticate to the vault directly:

```yaml
# GitHub Actions
- name: Run tests
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
  run: fnox exec -- npm test
```

The committed `fnox.toml` references resolve straight from 1Password using the [service account token](https://developer.1password.com/docs/service-accounts/). Alternatively, keep a separate set of [age-encrypted secrets in git](/providers/age) for CI.

## Next Steps

- [Syncing Secrets Locally](/guide/sync) - Everything `fnox sync` can do, including hardware-backed keys
- [Real-World Setup](/guide/real-world-example) - An alternative workflow with encrypted secrets in git
- [Profiles](/guide/profiles) - Different secrets for dev, staging, and production
- [Credential Leases](/guide/leases) - Short-lived credentials from long-lived masters
