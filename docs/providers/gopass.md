---
description: "Read and write gopass secrets with fnox. Configure an optional mount and resolve secrets through the gopass CLI."
---

# gopass

Integrate with [gopass](https://www.gopass.pw/), a CLI password manager that stores secrets encrypted with GPG (or age) and syncs them through Git. fnox shells out to the `gopass` CLI, so your existing stores, mounts and recipients keep working.

## Quick start

```sh
# Install gopass and initialize a store (one-time setup)
brew install gopass
gopass setup
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
gopass = { type = "gopass", mount = "company" } # mount is optional

[secrets]
DATABASE_URL = { provider = "gopass", value = "apps/myapp/database_url" }
GITHUB_TOKEN = { provider = "gopass", value = "shared/github/token" }
```

With the config above, `DATABASE_URL` is read with `gopass cat company/apps/myapp/database_url`. Without `mount`, the value is used as the gopass path as-is.

```sh
# Store a secret (written with `gopass insert -f`)
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider gopass

# Retrieve it
fnox get DATABASE_URL

# Use in shell commands
fnox exec -- npm start
```

## Configuration

| Field   | Required | Description                                                                                     |
| ------- | -------- | ----------------------------------------------------------------------------------------------- |
| `type`  | yes      | `gopass`                                                                                        |
| `mount` | no       | Store/mount name prepended to every secret path (`mount/value`). Leave unset for the root store |

## Errors

fnox reports a clear error when `gopass` is not installed, when the GPG key is locked or unavailable, or when the secret path does not exist.

Test the connection with:

```sh
fnox provider test gopass
```
