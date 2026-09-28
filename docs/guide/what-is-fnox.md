---
description: "Learn how fnox connects encrypted files and secret stores to your shell, applications, and CI jobs."
---

# What is fnox?

fnox is a command-line tool that loads secrets from encrypted files, password managers, and cloud services. It gives your application environment variables while keeping the storage and authentication choices in a versioned `fnox.toml` file.

```sh
fnox exec -- npm start
```

Your application reads its usual environment variables. fnox resolves them before starting the command.

## Choose where secrets live

| Storage model             | What goes in `fnox.toml`                                    | What you need to read it                                   |
| ------------------------- | ----------------------------------------------------------- | ---------------------------------------------------------- |
| Encrypted in the config   | Ciphertext and public encryption settings                   | A matching age key, hardware token, or access to a KMS key |
| In a vault or local store | The provider configuration and item reference               | Access to that provider                                    |
| Non-sensitive defaults    | Plaintext values such as `LOG_LEVEL = { default = "info" }` | No credentials                                             |

You can mix these models within a project. A development profile might use age while production reads AWS Secrets Manager. Cloning the repository gives you the configuration; access still depends on your keys or provider permissions.

See [how resolution works](/guide/how-it-works) and the [provider catalog](/providers/overview).

## The golden path

For a team that already uses a remote vault, a useful workflow is:

1. Keep secrets in the vault and commit their references in `fnox.toml`.
2. Run [`fnox sync`](/guide/sync) to encrypt a personal copy into the gitignored `fnox.local.toml` using a local provider such as age.
3. Use `fnox exec` or [shell integration](/guide/shell-integration) to read that copy without contacting the vault.

The vault remains the source of truth. The cache is a snapshot: run sync again after a secret changes. A personal age key can also use [hardware-backed decryption](/guide/sync#hardware-backed-decryption).

Follow the [vault and local cache walkthrough](/guide/golden-path). If you want to start without a vault, follow the [age quick start](/guide/quick-start).

## Choose how commands receive secrets

- **One command:** `fnox exec -- <command>` resolves secrets for that subprocess.
- **Your shell:** [shell integration](/guide/shell-integration) loads and unloads values as you change directories.
- **A file-based tool:** [`as_file = true`](/reference/configuration#as-file) supplies a temporary file path instead of the value.
- **An API client or agent:** the [credential proxy](/guide/proxy) supplies placeholders and injects credentials into matching requests. The [MCP server](/guide/mcp) offers selected secret retrieval and command execution.

Use [profiles](/guide/profiles) for environment-specific settings and [hierarchical configuration](/guide/hierarchical-config) to share configuration across directories.

## Why a standalone CLI?

Secret resolution has its own lifecycle: authentication prompts, remote reads, local decryption, cache refreshes, and credential expiry. Keeping that lifecycle in fnox lets it work with any shell, task runner, or CI system.

[mise](/guide/mise-integration) can install fnox and run tasks through `fnox exec`. fnox handles secret resolution, including its optional [memory cache](/guide/daemon) and [encrypted sync cache](/guide/sync).
