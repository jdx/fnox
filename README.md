# fnox

**Fort Knox for your secrets.**

[![CI](https://github.com/jdx/fnox/actions/workflows/ci.yml/badge.svg)](https://github.com/jdx/fnox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

fnox reads secrets from encrypted files, password managers, and cloud secret stores, and hands them to your program as environment variables. One `fnox.toml` says where each secret lives, and the same command works on your laptop and in CI:

```sh
fnox exec -- npm start
```

**[Documentation](https://fnox.jdx.dev)** · [Quick start](https://fnox.jdx.dev/guide/quick-start) · [Providers](https://fnox.jdx.dev/providers/overview) · [CLI reference](https://fnox.jdx.dev/cli/)

## What it looks like

```toml
# fnox.toml — safe to commit
[providers.age]
type = "age"
recipients = ["age1..."]           # public keys of everyone who may decrypt

[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "age", value = "YWdl..." }   # ciphertext written by `fnox set`
STRIPE_KEY = { provider = "op", value = "Stripe/secret-key" } # a 1Password item
LOG_LEVEL = { default = "info" }                          # plain, non-sensitive setting

[profiles.production.providers.aws]
type = "aws-sm"
region = "us-east-1"
prefix = "myapp/"

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" } # AWS Secrets Manager in production
```

```sh
fnox exec -- npm start                       # development values
fnox exec --profile production -- ./deploy   # production values
```

Your program just reads `DATABASE_URL`. Nothing sensitive is in git: encrypted values need a private key to read, and vault references need access to the vault.

## Install

```sh
mise use -g fnox
```

Or `cargo install fnox --locked`, `nix profile install github:jdx/fnox`, or a binary from [GitHub Releases](https://github.com/jdx/fnox/releases). See [installation](https://fnox.jdx.dev/guide/installation).

## Get started

- **No vault yet?** The [quick start](https://fnox.jdx.dev/guide/quick-start) encrypts your first secret with age in about five minutes.
- **Already use 1Password, Bitwarden, AWS, Vault, …?** [Use an existing vault](https://fnox.jdx.dev/guide/existing-vault): commit references and optionally cache values locally.

## Features

- **[Mix providers](https://fnox.jdx.dev/providers/overview)** per secret: encrypted in git, password managers, cloud secret stores, local keychains.
- **[Profiles](https://fnox.jdx.dev/guide/profiles)** for development, staging, and production, plus [layered config files](https://fnox.jdx.dev/guide/config-files) for monorepos and personal overrides.
- **[Shell integration](https://fnox.jdx.dev/guide/shell-integration)** loads secrets when you `cd` into a project (Bash, Zsh, Fish, Nushell, PowerShell).
- **[Offline cache](https://fnox.jdx.dev/guide/sync)** of vault secrets, encrypted to your own key, optionally behind Touch ID or a YubiKey; or an in-memory [daemon](https://fnox.jdx.dev/guide/daemon).
- **[Short-lived credentials](https://fnox.jdx.dev/guide/leases)** from AWS STS, GCP, Azure, GitHub, GitLab, Vault, Cloudflare, Tailscale, Kubernetes, any OAuth2 token endpoint, or your own command.
- **[Safe for AI agents](https://fnox.jdx.dev/guide/proxy)**: a credential proxy injects real keys only into approved requests, and an [MCP server](https://fnox.jdx.dev/guide/mcp) exposes only the secrets you allow.
- **[CI-ready](https://fnox.jdx.dev/guide/ci)**: one credential for the runner, the same `fnox exec` command, log masking on GitHub Actions.

## Providers

| Where values live        | Providers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Encrypted in `fnox.toml` | [age](https://fnox.jdx.dev/providers/age), [FIDO2](https://fnox.jdx.dev/providers/fido2), [YubiKey](https://fnox.jdx.dev/providers/yubikey), [AWS KMS](https://fnox.jdx.dev/providers/aws-kms), [Azure Key Vault keys](https://fnox.jdx.dev/providers/azure-kms), [Google Cloud KMS](https://fnox.jdx.dev/providers/gcp-kms)                                                                                                                                                                                                                                                                                                                                               |
| Cloud and hosted stores  | [AWS Secrets Manager](https://fnox.jdx.dev/providers/aws-sm), [AWS Parameter Store](https://fnox.jdx.dev/providers/aws-ps), [Azure Key Vault](https://fnox.jdx.dev/providers/azure-sm), [Azure App Configuration](https://fnox.jdx.dev/providers/azure-ac), [Google Secret Manager](https://fnox.jdx.dev/providers/gcp-sm), [Kubernetes](https://fnox.jdx.dev/providers/kubernetes), [HashiCorp Vault](https://fnox.jdx.dev/providers/vault), [Doppler](https://fnox.jdx.dev/providers/doppler), [FOKS](https://fnox.jdx.dev/providers/foks), [Bitwarden Secrets Manager](https://fnox.jdx.dev/providers/bitwarden-sm), [Keeper](https://fnox.jdx.dev/providers/keeper-sm) |
| Password managers        | [1Password](https://fnox.jdx.dev/providers/1password), [Bitwarden](https://fnox.jdx.dev/providers/bitwarden), [Enpass](https://fnox.jdx.dev/providers/enpass), [Infisical](https://fnox.jdx.dev/providers/infisical), [Passwordstate](https://fnox.jdx.dev/providers/passwordstate), [Proton Pass](https://fnox.jdx.dev/providers/proton-pass)                                                                                                                                                                                                                                                                                                                             |
| Local stores             | [OS keychain](https://fnox.jdx.dev/providers/keychain), [KeePass](https://fnox.jdx.dev/providers/keepass), [password-store](https://fnox.jdx.dev/providers/password-store), [gopass](https://fnox.jdx.dev/providers/gopass)                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Your own                 | [Lua plugins](https://fnox.jdx.dev/providers/lua)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and tests. Report bugs in the [issue tracker](https://github.com/jdx/fnox/issues); ask questions in [Discussions](https://github.com/jdx/fnox/discussions).

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
