---
description: "Look up the environment variables fnox reads: profile and missing-secret overrides, age keys, directories, daemon, shell output, and provider credentials."
---

# Environment variables

fnox reads these variables at startup. A command-line flag beats the matching variable, and most variables beat the corresponding setting in `fnox.toml`. Provider credentials and lease inputs follow their own rules, documented on each provider and lease page.

## Selection and behavior

| Variable                                                      | Values                                               | Default   | Effect                                                                                                                               |
| ------------------------------------------------------------- | ---------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `FNOX_PROFILE`                                                | profile names, comma-separated                       | `default` | Active profiles; later ones override earlier ones. `-P` overrides it.                                                                |
| `FNOX_NO_DEFAULTS`                                            | `true` or `1`                                        | `false`   | A named profile leaves out top-level `[secrets]`. Same as `--no-defaults`.                                                           |
| `FNOX_IF_MISSING`                                             | `error`, `warn`, `ignore`                            | unset     | Missing-secret behavior for every secret, overriding the config. `--if-missing` overrides it.                                        |
| `FNOX_IF_MISSING_DEFAULT`                                     | `error`, `warn`, `ignore`                            | `warn`    | Missing-secret behavior for secrets whose config sets none.                                                                          |
| <span id="fnox-non-interactive"></span>`FNOX_NON_INTERACTIVE` | `true` or `1`                                        | unset     | Never prompt or open a browser. Same as `--non-interactive`.                                                                         |
| `FNOX_PROMPT_AUTH`                                            | `true`, `1`, `yes`; anything else is false           | `true`    | Offer to run a provider's `auth_command` when authentication fails in a terminal. Overrides `prompt_auth` in the config.             |
| `FNOX_EXEC_REDACT`                                            | `true`, `1`, `yes`, `on`; anything else is false     | unset     | Redact secret values from piped `fnox exec` output. Overrides `redact_exec` in the config; `--redact` / `--no-redact` override it.   |
| `FNOX_DAEMON`                                                 | `on`, `true`, `yes`, `1` / `off`, `false`, `no`, `0` | unset     | Use the per-user daemon, or bypass it, regardless of `[daemon] enabled`. Other values are ignored.                                   |
| `FNOX_AUDIT`                                                  | `on`, `true`, `yes`, `1` / `off`, `false`, `no`, `0` | unset     | Write or skip the [audit log](/guide/audit), regardless of `[audit] enabled`. Other values are ignored.                              |
| `FNOX_AUDIT_PATH`                                             | absolute path                                        | unset     | Audit log file, overriding `[audit] path` and the default `audit.log` in the state directory.                                        |
| <span id="fnox-http-timeout"></span>`FNOX_HTTP_TIMEOUT`       | duration such as `30s` or `2m`; `0` for none         | `30s`     | Timeout for HTTP requests fnox makes itself: lease backends, Lua plugins, and Azure App Configuration. An invalid value means `30s`. |
| `FNOX_SHELL_OUTPUT`                                           | `none`, `normal`, `debug`                            | `normal`  | What shell integration prints. `off`, `false`, and `0` also mean `none`; `verbose` also means `debug`.                               |

For the full order in which `--if-missing`, these variables, and the config combine, see [`if_missing`](/reference/configuration#if-missing). For the settings that have a flag, see [runtime settings](/cli/configuration).

## age keys

| Variable            | Effect                                                                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `FNOX_AGE_KEY`      | age identity contents. Takes precedence over every other identity source, including the provider's `identity` and `key_file`.               |
| `FNOX_AGE_KEY_FILE` | Path to an age identity or SSH private key. Used only when `FNOX_AGE_KEY` is unset and the provider sets neither `identity` nor `key_file`. |

Without either, fnox reads `age.txt` in `FNOX_CONFIG_DIR`. `fnox exec` removes both variables from the command's environment. See [age identity selection](/providers/age#set-decryption-key).

## Directories

These variables take an absolute path; fnox ignores relative or empty values. The defaults follow the XDG base directory variables when set.

### `FNOX_CONFIG_DIR`

Directory for the global `config.toml` and the default `age.txt` identity. Default: `$XDG_CONFIG_HOME/fnox`, else `~/.config/fnox` on Unix and `%USERPROFILE%\AppData\Local\fnox` on Windows.

### `FNOX_STATE_DIR`

Directory for the per-project lease ledgers, under `leases/`. Default: `$XDG_STATE_HOME/fnox`, else `~/.local/state/fnox` on Unix and `%USERPROFILE%\AppData\Local\fnox` on Windows.

### `FNOX_DATA_DIR`

Data directory. Default: `$XDG_DATA_HOME/fnox`, else `~/.local/share/fnox` on Unix and `%USERPROFILE%\AppData\Local\fnox` on Windows.

### `FNOX_PLUGINS_DIR`

Directory for installed [Lua plugins](/providers/lua), one subdirectory per plugin. Default: `$FNOX_DATA_DIR/plugins`.

## Editor and logging

| Variable   | Effect                                                                                             |
| ---------- | -------------------------------------------------------------------------------------------------- |
| `EDITOR`   | Editor for `fnox edit`. Default: `vi`, or `notepad` on Windows.                                    |
| `VISUAL`   | Used by `fnox edit` when `EDITOR` is unset.                                                        |
| `RUST_LOG` | Log filter for stderr, such as `fnox=debug`. Takes precedence over the default set by `--verbose`. |

## Provider and lease credentials

Most providers read credentials from the environment, usually under both their own name and a `FNOX_`-prefixed name. Provider config can override them. Each page gives the precedence.

| Provider                  | Variables                                                                                      | Details                                                           |
| ------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| AWS                       | `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION` | [AWS credentials](/providers/aws-sm#configure-aws-credentials)    |
| Azure                     | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_AUTHORITY_HOST`            | [Azure authentication](/providers/azure-sm#authentication)        |
| Google Cloud              | `GOOGLE_APPLICATION_CREDENTIALS`                                                               | [Google Cloud authentication](/providers/gcp-sm#authentication)   |
| Kubernetes                | `FNOX_K8S_CONTEXT`, `KUBECONFIG`                                                               | [Kubernetes](/providers/kubernetes#configuration)                 |
| 1Password                 | `FNOX_OP_SERVICE_ACCOUNT_TOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`                                    | [1Password](/providers/1password#authentication)                  |
| Bitwarden                 | `FNOX_BW_SESSION`, `BW_SESSION`                                                                | [Bitwarden](/providers/bitwarden)                                 |
| Bitwarden Secrets Manager | `FNOX_BWS_ACCESS_TOKEN`, `BWS_ACCESS_TOKEN`, `BWS_PROJECT_ID`                                  | [Bitwarden SM](/providers/bitwarden-sm#environment-variables)     |
| Doppler                   | `FNOX_DOPPLER_TOKEN`, `DOPPLER_TOKEN`                                                          | [Doppler](/providers/doppler#token-management)                    |
| Enpass                    | `FNOX_ENPASS_PASSWORD`, `ENPASS_PASSWORD`                                                      | [Enpass](/providers/enpass#authentication)                        |
| FOKS                      | `FOKS_BOT_TOKEN`, `FOKS_HOST`, `FOKS_HOME`, and `FNOX_` equivalents                            | [FOKS](/providers/foks#cicd)                                      |
| Infisical                 | `INFISICAL_TOKEN`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, and `FNOX_` equivalents   | [Infisical](/providers/infisical)                                 |
| KeePass                   | `FNOX_KEEPASS_PASSWORD`, `KEEPASS_PASSWORD`                                                    | [KeePass](/providers/keepass#authentication)                      |
| Keeper Secrets Manager    | `FNOX_KEEPER_CONFIG`, `KSM_CONFIG`, `FNOX_KEEPER_TOKEN`, `KSM_TOKEN`                           | [Keeper SM](/providers/keeper-sm#authentication)                  |
| Passwordstate             | `FNOX_PASSWORDSTATE_API_KEY`, `PASSWORDSTATE_API_KEY`                                          | [Passwordstate](/providers/passwordstate)                         |
| password-store            | `PASSWORD_STORE_DIR`, `PASSWORD_STORE_GPG_OPTS`, and `FNOX_` equivalents                       | [password-store](/providers/password-store#environment-variables) |
| Proton Pass               | `PROTON_PASS_PERSONAL_ACCESS_TOKEN`, `PROTON_PASS_AGENT_REASON`, and `FNOX_` equivalents       | [Proton Pass](/providers/proton-pass#session-and-key-storage)     |
| Vault                     | `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, and `FNOX_` equivalents                        | [Vault](/providers/vault)                                         |

Lease backends read the same cloud credentials, plus backend-specific inputs such as `FNOX_GITHUB_APP_PRIVATE_KEY` for [`github-app`](/leases/github-app). See [credential leases](/guide/leases).

## Set by fnox

fnox sets these variables for other processes. Do not set them yourself.

| Variable                                  | Set for                                                                                      |
| ----------------------------------------- | -------------------------------------------------------------------------------------------- |
| `FNOX_SHELL`, `__FNOX_SESSION`            | The shell, by `fnox activate`. They record the active shell and the secrets the hook loaded. |
| `FNOX_LEASE_DURATION`, `FNOX_LEASE_LABEL` | A [`command`](/leases/command) lease's `create_command`.                                     |
| `FNOX_LEASE_ID`                           | A `command` lease's `revoke_command`.                                                        |

## See also

- [Configuration reference](/reference/configuration): the `fnox.toml` settings these variables override.
- [Runtime settings](/cli/configuration): settings available as both a flag and a variable.
- [CI/CD](/guide/ci): non-interactive authentication in pipelines.
