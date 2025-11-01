# `fnox set`

- **Usage**: `fnox set [FLAGS] <KEY> [VALUE]`
- **Aliases**: `s`

Set a secret value

## Arguments

### `<KEY>`

Secret key (environment variable name)

### `[VALUE]`

Secret value (reads from stdin if not provided)

## Flags

### `-d --description <DESCRIPTION>`

Description of the secret

### `-k --key-name <KEY_NAME>`

Key name in the provider (if different from env var name)

### `-p --provider <PROVIDER>`

Provider to fetch from

### `--default <DEFAULT>`

Default value to use if secret is not found

### `--if-missing <IF_MISSING>`

What to do if the secret is missing (error, warn, ignore)

**Choices:**

- `error`
- `warn`
- `ignore`
