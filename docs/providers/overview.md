---
description: "Choose a fnox provider by need, compare storage models, write support and requirements, and mix providers in one project."
---

# Provider catalog

A provider is where fnox gets a secret's value: ciphertext in `fnox.toml`, a cloud secret store, a password manager, or a store on your machine. Use this page to pick one, then follow its page for authentication and reference formats.

## How providers work

You declare a provider instance under `[providers.<name>]`. The table name is yours to choose; `type` selects the implementation. Each secret names the instance it reads from:

```toml
[providers.op]          # instance name "op"
type = "1password"      # provider type
vault = "Engineering"

[providers.age]
type = "age"
recipients = ["age1..."]

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }      # a reference into 1Password
LOCAL_TOKEN = { provider = "age", value = "YWdl..." }           # ciphertext, abbreviated
```

- **Mix freely.** One project can use any number of instances, including several of the same type (for example one per vault or region).
- **Default provider.** A secret without `provider` uses `default_provider`. When exactly one provider is configured, fnox uses it automatically.
- **What `value` means depends on the type.** Encryption providers store ciphertext; remote and local storage providers store a reference (a name, path or ID) and keep the value in their own store; the `plain` provider stores the value unencrypted in `fnox.toml`.
- **Swap per environment.** Redefine an instance in a [profile](/guide/profiles) to point the same secret names at a different vault or account.

Add an instance with `fnox provider add <name> <type>` or by editing `fnox.toml`, then check it with `fnox provider test <name>`.

## Choose by need

| You want to…                                    | Use                                                                                                                                                                                       |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Start without any account or service            | [age](/providers/age) ([quick start](/guide/quick-start))                                                                                                                                 |
| Commit encrypted secrets and share them by key  | [age](/providers/age), or a cloud KMS ([AWS](/providers/aws-kms), [Azure](/providers/azure-kms), [GCP](/providers/gcp-kms)) to control decryption with IAM                                |
| Require a hardware key to decrypt               | [FIDO2](/providers/fido2), [YubiKey](/providers/yubikey), or an [age plugin](/providers/age)                                                                                              |
| Read what your team already keeps in a vault    | [1Password](/providers/1password), [Bitwarden](/providers/bitwarden), [HashiCorp Vault](/providers/vault), or your cloud's secret manager ([existing vault guide](/guide/existing-vault)) |
| Write secrets to a cloud store with `fnox set`  | [AWS Secrets Manager](/providers/aws-sm), [AWS Parameter Store](/providers/aws-ps), [Azure Key Vault Secrets](/providers/azure-sm), [Google Cloud Secret Manager](/providers/gcp-sm)      |
| Keep a personal or bootstrap credential locally | [OS keychain](/providers/keychain)                                                                                                                                                        |
| Read vault secrets offline or faster            | Any provider plus a [local sync cache](/guide/sync) or the [daemon](/guide/daemon)                                                                                                        |
| Get short-lived cloud credentials               | [Credential leases](/guide/leases), configured separately from providers                                                                                                                  |
| Integrate a system with no built-in provider    | A [Lua plugin](/providers/lua)                                                                                                                                                            |

"Writes" in the tables below means `fnox set KEY` stores the value through the provider. For a read-only provider, `fnox set KEY VALUE --provider <name>` records `VALUE` as the reference instead; create the item in the provider's own app or CLI. `fnox import` currently accepts encryption providers only.

## Encryption in config {#encryption-in-your-config}

`fnox set` encrypts the value and stores the ciphertext in `fnox.toml`. The config and public recipients can be committed; private keys and cloud credentials stay outside the repository.

| Provider                                     | Config type | Writes (`fnox set`) | Requires                                               |
| -------------------------------------------- | ----------- | ------------------- | ------------------------------------------------------ |
| [age](/providers/age)                        | `age`       | Yes                 | An age or SSH identity, or an age plugin, to decrypt   |
| [FIDO2](/providers/fido2)                    | `fido2`     | Yes                 | The enrolled security key with hmac-secret support     |
| [YubiKey](/providers/yubikey)                | `yubikey`   | Yes                 | The enrolled YubiKey with HMAC-SHA1 challenge-response |
| [AWS KMS](/providers/aws-kms)                | `aws-kms`   | Yes                 | AWS credentials with encrypt/decrypt access to the key |
| [Azure Key Vault Keys](/providers/azure-kms) | `azure-kms` | Yes                 | Azure credentials with access to the key               |
| [Google Cloud KMS](/providers/gcp-kms)       | `gcp-kms`   | Yes                 | Google Cloud credentials with access to the key        |

## Cloud and hosted stores

`fnox.toml` holds a reference; the value lives in the service, and the service's access policy decides who can read it.

| Provider                                             | Config type    | Writes (`fnox set`) | Requires                                                       |
| ---------------------------------------------------- | -------------- | ------------------- | -------------------------------------------------------------- |
| [AWS Parameter Store](/providers/aws-ps)             | `aws-ps`       | Yes                 | AWS credentials                                                |
| [AWS Secrets Manager](/providers/aws-sm)             | `aws-sm`       | Yes                 | AWS credentials                                                |
| [Azure App Configuration](/providers/azure-ac)       | `azure-ac`     | No (read-only)      | Azure credentials                                              |
| [Azure Key Vault Secrets](/providers/azure-sm)       | `azure-sm`     | Yes                 | Azure credentials                                              |
| [Google Cloud Secret Manager](/providers/gcp-sm)     | `gcp-sm`       | Yes                 | Google Cloud credentials                                       |
| [Kubernetes Secrets](/providers/kubernetes)          | `kubernetes`   | No (read-only)      | Kubeconfig or in-cluster credentials with `get` on the Secrets |
| [Bitwarden Secrets Manager](/providers/bitwarden-sm) | `bitwarden-sm` | Yes                 | `bws` CLI and a machine-account access token                   |
| [Doppler](/providers/doppler)                        | `doppler`      | No (read-only)      | `doppler` CLI, logged in or with a service token               |
| [FOKS](/providers/foks)                              | `foks`         | Yes                 | `foks` CLI with a running agent                                |
| [HashiCorp Vault](/providers/vault)                  | `vault`        | Yes                 | `vault` CLI, a server address and a token                      |
| [Keeper Secrets Manager](/providers/keeper-sm)       | `keeper-sm`    | No (read-only)      | A Keeper Secrets Manager client configuration                  |

## Password managers and services

These read from a vault people already use. All of them are read-only in fnox: create and edit items in the password manager, then reference them.

| Provider                                  | Config type     | Writes (`fnox set`) | Requires                                            |
| ----------------------------------------- | --------------- | ------------------- | --------------------------------------------------- |
| [1Password](/providers/1password)         | `1password`     | No (read-only)      | `op` CLI, signed in or with a service account token |
| [Bitwarden](/providers/bitwarden)         | `bitwarden`     | No (read-only)      | `bw` CLI and an unlocked session, or `rbw`          |
| [Enpass](/providers/enpass)               | `enpass`        | No (read-only)      | The local vault files and the master password       |
| [Infisical](/providers/infisical)         | `infisical`     | No (read-only)      | `infisical` CLI and a token or machine identity     |
| [Passwordstate](/providers/passwordstate) | `passwordstate` | No (read-only)      | Network access to the server and a list API key     |
| [Proton Pass](/providers/proton-pass)     | `proton-pass`   | No (read-only)      | `pass-cli`, logged in                               |

## Local stores and defaults

These use a store on your machine, or no storage beyond `fnox.toml` itself.

| Provider                                    | Config type      | Writes (`fnox set`)                         | Requires                                                            |
| ------------------------------------------- | ---------------- | ------------------------------------------- | ------------------------------------------------------------------- |
| [OS keychain](/providers/keychain)          | `keychain`       | Yes                                         | macOS Keychain, Windows Credential Manager, or Linux Secret Service |
| [KeePass](/providers/keepass)               | `keepass`        | Yes                                         | A `.kdbx` file and its password (and key file, if used)             |
| [password-store](/providers/password-store) | `password-store` | Yes                                         | `pass` CLI and a GPG key                                            |
| [gopass](/providers/gopass)                 | `gopass`         | Yes                                         | `gopass` CLI and an initialized store                               |
| [Plaintext defaults](/providers/plain)      | `plain`          | Yes, as plaintext in config; No with `file` | Nothing. Only for values that are not secret                        |

## Custom providers

| Provider                      | Config type | Writes (`fnox set`)                                        | Requires                                     |
| ----------------------------- | ----------- | ---------------------------------------------------------- | -------------------------------------------- |
| [Lua plugins](/providers/lua) | `lua`       | Yes if the plugin defines `encrypt` or `put`; otherwise No | A plugin file, directory or installed plugin |

A Lua plugin can read, store or encrypt values with HTTP, JSON and command helpers, and can be shared as a git repository.

## See also

- [Use an existing vault](/guide/existing-vault): connect a password manager or cloud store and cache it locally.
- [Configuration reference](/reference/configuration): fields shared by every provider, such as `auth_command` and `daemon_cache`.
- [Provider commands](/cli/provider): add, list, test and remove provider instances.
