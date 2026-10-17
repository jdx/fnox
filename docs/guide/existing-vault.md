---
description: "Reference secrets that already live in 1Password or another vault, commit only the references, and cache values locally for fast offline reads."
---

# Use an existing vault

If your team already keeps secrets in a vault, fnox doesn't move them. You commit _references_ to vault items in `fnox.toml`, and each person reads them with their own vault login. Optionally, `fnox sync` keeps an encrypted copy on your machine so everyday commands don't need the vault at all.

This page uses 1Password. The same steps work with any remote provider, such as [Bitwarden](/providers/bitwarden), [AWS Secrets Manager](/providers/aws-sm), [HashiCorp Vault](/providers/vault), or [Doppler](/providers/doppler); only the provider block and reference format change.

## Before you start

- [fnox installed](/guide/installation)
- The [1Password CLI](https://developer.1password.com/docs/cli/get-started/) (`op`) installed and signed in. Check with `op vault list`.

## 1. Reference your vault items

In your project, create `fnox.toml`:

```sh
fnox init --skip-wizard
```

Add a provider for the vault and a reference for each secret:

```toml
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
STRIPE_KEY = { provider = "op", value = "Stripe/secret-key" }
```

`op` is a name you choose for this provider; `1password` is its type. `Database/url` means "the `url` field of the `Database` item". See [1Password reference formats](/providers/1password#reference-formats) for the full syntax.

## 2. Check and run

```sh
fnox provider test op
fnox check --all
fnox exec -- npm start
```

Each command reads from 1Password through `op`, so you may be asked to authenticate. Commit `fnox.toml`: it contains vault, item, and field names, but no secret values.

At this point you have a working setup. The rest of this page is optional.

## 3. Cache locally (optional)

Reading from a remote vault on every command can be slow, and it doesn't work offline. `fnox sync` fetches every value once and stores it in a gitignored `fnox.local.toml`, encrypted to a personal age key. Later reads decrypt locally.

Create your personal key and a machine-wide provider for it. You do this once per machine:

```sh
mkdir -p ~/.config/fnox
age-keygen -o ~/.config/fnox/age.txt   # prints your public key (age1...)
fnox provider add sync-age age --global
```

Then edit `~/.config/fnox/config.toml` so the provider uses your public key:

```toml
[providers.sync-age]
type = "age"
recipients = ["age1..."] # your public key
```

Now sync the project:

```sh
echo "fnox.local.toml" >> .gitignore
fnox sync --provider sync-age --local-file
```

`fnox exec`, `fnox get`, and shell integration now read the cached values without calling 1Password.

The cache does not refresh by itself. After a value changes in the vault, sync again:

```sh
fnox sync --provider sync-age --local-file --force
```

The [sync guide](/guide/sync) explains what is written where, and how to keep the age key in hardware such as Touch ID, a YubiKey, or a TPM. If your vault authenticates with a long-lived service token rather than an interactive login, keep that token in the same cache too: see [protect the vault credential](/guide/sync#protect-the-vault-credential).

## 4. Load secrets in your shell (optional)

```sh
# ~/.zshrc
eval "$(fnox activate zsh)"
```

Secrets now load when you `cd` into the project and unload when you leave. See [shell integration](/guide/shell-integration) for other shells.

## Working as a team

- **New teammate:** grant them vault access. They clone the repo and run `fnox exec` (and, if they want a cache, steps 3–4 on their machine). Nothing else is shared.
- **New secret:** add the item to the vault, add its reference to `fnox.toml`, and commit. Anyone with a cache syncs again.
- **CI:** authenticate to the vault with a service account and run `fnox exec` as usual. See [CI/CD](/guide/ci).

## See also

- [Provider catalog](/providers/overview): every supported vault and its reference format.
- [Profiles](/guide/profiles): read a different vault for production.
- [Local sync cache](/guide/sync): hardware-backed keys and sync options.
