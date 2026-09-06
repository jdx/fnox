---
description: "Compare fnox providers by storage model and prerequisites, then find authentication and setup instructions."
---

# Choose a provider

A provider connects a secret name to its storage. Configure an instance under `[providers.<name>]`, then use that name in each secret's `provider` field. You can use several providers in one project.

## Start with your storage model

| You want to…                               | Start here                                                                                                | Keep in mind                                                       |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Get started without a cloud account        | [age quick start](/guide/quick-start)                                                                     | Keep the private key outside git and back it up                    |
| Use your team's existing vault             | [Connect a vault](/guide/golden-path)                                                                     | Each user or CI identity needs access                              |
| Read remote secrets offline                | [Sync to a local age cache](/guide/sync)                                                                  | Refresh the snapshot after values change                           |
| Use cloud IAM to control decryption        | AWS, Azure, or GCP KMS below                                                                              | Encrypt and decrypt operations need the cloud API                  |
| Bind encryption to a hardware token        | [FIDO2](/providers/fido2), [YubiKey](/providers/yubikey), or [age plugins](/providers/age#plugin-support) | Native providers need the token for both encryption and decryption |
| Keep a bootstrap credential on one machine | [OS keychain](/providers/keychain)                                                                        | The credential store must be available and unlocked                |
| Generate temporary credentials             | [Credential leases](/guide/leases)                                                                        | Lease backends are configured separately from providers            |

## Encryption in your config

`fnox set` stores ciphertext in `fnox.toml`. The config and public recipients can be committed; private keys and bootstrap credentials stay outside the repository.

| Provider                                     | Config type | Decryption requires                                    |
| -------------------------------------------- | ----------- | ------------------------------------------------------ |
| [age](/providers/age)                        | `age`       | An age or supported SSH identity, or an age plugin     |
| [FIDO2](/providers/fido2)                    | `fido2`     | The original token with hmac-secret support            |
| [YubiKey](/providers/yubikey)                | `yubikey`   | The original HMAC challenge-response key               |
| [AWS KMS](/providers/aws-kms)                | `aws-kms`   | AWS credentials and permission to decrypt with the key |
| [Azure Key Vault Keys](/providers/azure-kms) | `azure-kms` | Azure credentials and access to the key                |
| [Google Cloud KMS](/providers/gcp-kms)       | `gcp-kms`   | Google Cloud credentials and access to the key         |

## Cloud and hosted stores

`fnox.toml` contains references to values held by the service. Provider permissions control access to those values. Rotation and audit features depend on the service and its configuration; fnox does not enable them automatically.

| Provider                                             | Config type    | Reference points to                                    |
| ---------------------------------------------------- | -------------- | ------------------------------------------------------ |
| [AWS Secrets Manager](/providers/aws-sm)             | `aws-sm`       | A secret name, optionally with `json_path` for a field |
| [AWS Parameter Store](/providers/aws-ps)             | `aws-ps`       | A parameter name or path                               |
| [Azure Key Vault Secrets](/providers/azure-sm)       | `azure-sm`     | A secret name                                          |
| [Azure App Configuration](/providers/azure-ac)       | `azure-ac`     | A non-secret configuration key and optional label      |
| [Google Cloud Secret Manager](/providers/gcp-sm)     | `gcp-sm`       | A secret name                                          |
| [HashiCorp Vault](/providers/vault)                  | `vault`        | A KV secret and field                                  |
| [Doppler](/providers/doppler)                        | `doppler`      | A secret key in a project/config                       |
| [FOKS](/providers/foks)                              | `foks`         | A key in a personal or team namespace                  |
| [Bitwarden Secrets Manager](/providers/bitwarden-sm) | `bitwarden-sm` | A secret key in a project                              |
| [Keeper Secrets Manager](/providers/keeper-sm)       | `keeper-sm`    | A record and field using Keeper notation               |

## Password managers and secret services

These providers use an existing vault or service account. Follow the individual guide for the CLI or API authentication needed on each machine.

| Provider                                  | Config type     | Integration                                   |
| ----------------------------------------- | --------------- | --------------------------------------------- |
| [1Password](/providers/1password)         | `1password`     | `op` CLI; item and field references           |
| [Bitwarden](/providers/bitwarden)         | `bitwarden`     | `bw` CLI, or the experimental `rbw` backend   |
| [Infisical](/providers/infisical)         | `infisical`     | Infisical CLI; project, environment, and path |
| [Passwordstate](/providers/passwordstate) | `passwordstate` | HTTP API; password ID or title and field      |
| [Proton Pass](/providers/proton-pass)     | `proton-pass`   | `pass-cli`; vault, item, and field            |

## Local stores and defaults

These use a store available on your machine, or no encrypted storage at all for plaintext defaults.

| Provider                                    | Config type      | Storage                                                             |
| ------------------------------------------- | ---------------- | ------------------------------------------------------------------- |
| [OS keychain](/providers/keychain)          | `keychain`       | macOS Keychain, Windows Credential Manager, or Linux Secret Service |
| [KeePass](/providers/keepass)               | `keepass`        | A local `.kdbx` file                                                |
| [password-store](/providers/password-store) | `password-store` | GPG-encrypted files managed by `pass`                               |
| [Plaintext](/providers/plain)               | `plain`          | Unencrypted values; only for non-sensitive configuration            |

## Configure an instance

This example reads an existing item from 1Password:

```toml
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
```

Test the configured instance, then resolve the secret:

```sh
fnox provider test op
fnox get DATABASE_URL
fnox exec -- npm start
```

`fnox get` prints the resolved value. `fnox list` lists the secrets configured in fnox; it is not a directory of every item in your remote vault.

A provider's read and write capabilities may differ. In particular, a read-only provider cannot be used with `fnox set`, and `fnox import` currently accepts encryption providers only. Check the provider guide before choosing a write or migration workflow.

## Next steps

- [Configuration reference](/reference/configuration): common provider fields and secret options.
- [Profiles](/guide/profiles): select different providers for different environments.
- [Troubleshooting](/guide/troubleshooting): diagnose a provider connection or missing value.
