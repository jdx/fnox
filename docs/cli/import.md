# `fnox import`

- **Usage**: `fnox import <FLAGS> [FORMAT]`
- **Aliases**: `im`

Import secrets from various sources

## Arguments

### `[FORMAT]`

Import source format

**Choices:**

- `env`
- `json`
- `yaml`
- `toml`

**Default:** `env`

## Flags

### `-f --force`

Skip confirmation prompts

### `-i --input <INPUT>`

Source file or path to import from (default: stdin)

### `-p --provider <PROVIDER>`

Provider to use for encrypting/storing imported secrets (required)

### `--filter <FILTER>`

Only import matching secrets (regex pattern)

### `--prefix <PREFIX>`

Prefix to add to imported secret names
