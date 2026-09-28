# fnox

**Fort Knox for your secrets.**

[![CI](https://github.com/jdx/fnox/actions/workflows/ci.yml/badge.svg)](https://github.com/jdx/fnox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

fnox loads secrets into your commands from encrypted files, password managers, and cloud services. Keep the configuration in `fnox.toml`, choose where each secret lives, and use the same command in development and CI:

```sh
fnox exec -- npm start
```

[Documentation](https://fnox.jdx.dev) · [Quick start](https://fnox.jdx.dev/guide/quick-start) · [Providers](https://fnox.jdx.dev/providers/overview) · [CLI reference](https://fnox.jdx.dev/cli/)

## Get started

Install with [mise](https://mise.jdx.dev):

```sh
mise use -g fnox
```

Or with Rust: `cargo install fnox --locked`. See [installation](https://fnox.jdx.dev/guide/installation) for other methods and updates.

In your project, run the setup wizard and configure a provider before storing a secret:

```sh
fnox init

# Use the default provider selected in the wizard; the value is prompted
fnox set DATABASE_URL

# Check access, then run your application
fnox check --all
fnox exec -- npm start
```

The provider determines where the value is stored. **Without a provider, `fnox set` writes a plaintext default.** Follow the [age quick start](https://fnox.jdx.dev/guide/quick-start) for a complete encrypted setup, or [connect an existing vault](https://fnox.jdx.dev/guide/golden-path).

## One config, your choice of storage

With a remote provider, `value` is a reference. This example reads an existing 1Password item:

```toml
# fnox.toml
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
LOG_LEVEL = { default = "info" } # Non-sensitive configuration

[profiles.production.providers.aws]
type = "aws-sm"
region = "us-east-1"
prefix = "myapp/"

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }
```

```sh
fnox exec -- npm start
fnox exec --profile production -- ./deploy.sh
```

With an encryption provider, `fnox set` writes ciphertext into `fnox.toml`. Commit the ciphertext and public recipients; keep private keys outside the repository. Teammates need a matching private key or access to the configured vault.

## Fit secrets into your workflow

- **[Load on directory change](https://fnox.jdx.dev/guide/shell-integration).** Shell hooks load and unload secrets as you move between projects. Bash, Zsh, Fish, Nushell, and PowerShell are supported.
- **[Cache a vault locally](https://fnox.jdx.dev/guide/sync).** `fnox sync` encrypts a personal cache for offline use with a local provider such as age. Refresh it when vault values change.
- **[Cache in memory](https://fnox.jdx.dev/guide/daemon).** The optional daemon reuses resolved values during your session.
- **[Separate environments](https://fnox.jdx.dev/guide/profiles).** Compose profiles, share settings across a monorepo, and keep personal overrides in `fnox.local.toml`.
- **[Use temporary credentials](https://fnox.jdx.dev/guide/leases).** Create short-lived credentials with AWS STS, GitHub Apps, Vault, and other lease backends.
- **[Scope agent access](https://fnox.jdx.dev/guide/proxy).** Pass placeholders to a command and inject credentials into matching HTTPS requests. An [MCP server](https://fnox.jdx.dev/guide/mcp) also exposes selected secrets and command execution.

## Providers

Mix providers in the same project. Each provider guide covers authentication, configuration, and reference formats.

| Where values live                     | Providers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Encrypted in your config              | [age](https://fnox.jdx.dev/providers/age), [FIDO2](https://fnox.jdx.dev/providers/fido2), [YubiKey](https://fnox.jdx.dev/providers/yubikey), [AWS KMS](https://fnox.jdx.dev/providers/aws-kms), [Azure KMS](https://fnox.jdx.dev/providers/azure-kms), [GCP KMS](https://fnox.jdx.dev/providers/gcp-kms)                                                                                                                                                                                                                                                                                                             |
| Cloud and hosted stores               | [AWS Secrets Manager](https://fnox.jdx.dev/providers/aws-sm), [AWS Parameter Store](https://fnox.jdx.dev/providers/aws-ps), [Azure Key Vault](https://fnox.jdx.dev/providers/azure-sm), [Azure App Configuration](https://fnox.jdx.dev/providers/azure-ac), [GCP Secret Manager](https://fnox.jdx.dev/providers/gcp-sm), [Vault](https://fnox.jdx.dev/providers/vault), [Doppler](https://fnox.jdx.dev/providers/doppler), [FOKS](https://fnox.jdx.dev/providers/foks), [Bitwarden Secrets Manager](https://fnox.jdx.dev/providers/bitwarden-sm), [Keeper Secrets Manager](https://fnox.jdx.dev/providers/keeper-sm) |
| Password managers and secret services | [1Password](https://fnox.jdx.dev/providers/1password), [Bitwarden](https://fnox.jdx.dev/providers/bitwarden), [Infisical](https://fnox.jdx.dev/providers/infisical), [Passwordstate](https://fnox.jdx.dev/providers/passwordstate), [Proton Pass](https://fnox.jdx.dev/providers/proton-pass)                                                                                                                                                                                                                                                                                                                        |
| Local stores                          | [OS keychain](https://fnox.jdx.dev/providers/keychain), [KeePass](https://fnox.jdx.dev/providers/keepass), [password-store](https://fnox.jdx.dev/providers/password-store)                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Non-sensitive configuration           | [Plaintext defaults](https://fnox.jdx.dev/providers/plain)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

See the [provider comparison](https://fnox.jdx.dev/providers/overview) to choose a storage model. Cloud KMS providers require network access even though their ciphertext lives locally.

## Contribute

Start with [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, tests, and documentation changes. Report bugs in the [issue tracker](https://github.com/jdx/fnox/issues).

## Sponsors

<p align="center">
  Sponsored by<br><br>
  <a href="https://entire.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://jdx.dev/sponsors/entire-lockup.svg">
      <img src="https://jdx.dev/sponsors/entire-lockup-on-light.svg" alt="Entire" height="36">
    </picture>
  </a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://omarchy.org/patrons/">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://jdx.dev/sponsors/omacom-foundation.svg">
      <img src="https://jdx.dev/sponsors/omacom-foundation-on-light.svg" alt="Omacom Foundation" height="36">
    </picture>
  </a>
  <br><br>
  <a href="https://jdx.dev/sponsors.html">View all sponsors</a>
</p>

## License

[MIT](LICENSE)
