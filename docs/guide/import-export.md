---
description: "Move secrets from a .env, JSON, YAML, or TOML file into fnox, export resolved values for other tools, and migrate between providers."
---

# Import and export

`fnox import` encrypts values from an existing file into `fnox.toml`. `fnox export` writes resolved values out in another format. Together they cover moving off `.env` files and moving between providers.

## Import a `.env` file

Configure an encryption provider first (the [quick start](/guide/quick-start) sets up age), then preview and import:

```sh
fnox import -i .env --provider age --dry-run
fnox import -i .env --provider age
fnox check --all
```

Each `KEY=value` line becomes an encrypted secret in `fnox.toml`. Review the result, commit it, and delete `.env` once nothing needs it.

The import target must be an encryption provider, such as `age`, `aws-kms`, `yubikey`, or `fido2`. Importing into a remote store such as 1Password isn't supported; create those items with the vendor's tools and reference them instead.

### Other formats and sources

```sh
fnox import -i secrets.json json --provider age
fnox import -i secrets.yaml yaml --provider age
fnox import -i secrets.toml toml --provider age
cat .env | fnox import --provider age --force   # stdin
```

JSON, YAML, and TOML input is a flat map of names to values. When reading from stdin, pass `--force` (or `--dry-run`): fnox can't ask for confirmation on the stream it is reading secrets from.

### Select and rename

```sh
fnox import -i .env --provider age --filter '^DATABASE_'   # only matching names (regex)
fnox import -i .env --provider age --prefix 'LEGACY_'      # DATABASE_URL → LEGACY_DATABASE_URL
```

Add `--profile staging` to import into a profile, or `--global` to import into your global config.

## Export

```sh
fnox export                       # KEY=value
fnox export --format shell        # export KEY=value, for `source`
fnox export --format json         # also yaml, toml
fnox export -o .env               # write to a file
fnox export --profile production --format json
```

Exported values are **plaintext**. Wrapping a command in [`fnox exec`](/guide/running-commands) is safer whenever the tool allows it. If you must write a file, restrict its permissions (`umask 077` first) and keep it out of git.

Notes:

- Export follows shell rules: secrets with `env = "exec"` or `env = false` are left out unless you add `--all`.
- `as_file` secrets export as paths to temporary files, not their contents.
- JSON, YAML, and TOML output wraps values in a `secrets` object next to `metadata`. Use `jq '.secrets'` to get a flat map that `fnox import` accepts.
- Programs that start processes should use [`fnox env --json`](/reference/env-json) instead. It handles file secrets and variables to unset, and reports errors as JSON.

## Recipes

### Move from a vault to encrypted values

To keep the vault as the source of truth and only speed up reads, use [`fnox sync`](/guide/sync) instead. To copy values out of the vault permanently:

```sh
fnox export --profile production --format json --all |
  jq '.secrets' |
  fnox import json --provider age --profile production --force
```

### Docker Compose

`fnox exec -- docker compose up` passes secrets for Compose's `${VAR}` interpolation without writing a file. Use `fnox export -o .env` only if a service needs an `env_file`.

### Kubernetes

This uses process substitution, so run it in Bash or Zsh:

```sh
kubectl create secret generic app-secrets --from-env-file=<(fnox export)
```

### An onboarding template

`fnox export` always writes real values, whatever the file is called. Write example files by hand:

```json
{ "DATABASE_URL": "postgresql://localhost/example", "API_KEY": "replace-me" }
```

A teammate fills in a private copy and runs `fnox import -i secrets.json json --provider age`.

## See also

- [Running commands](/guide/running-commands): `exec`, `get`, and file secrets.
- [`fnox import` reference](/cli/import) and [`fnox export` reference](/cli/export): every flag.
- [Local sync cache](/guide/sync): cache a vault without migrating off it.
