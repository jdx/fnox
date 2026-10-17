---
description: "Read and write FOKS end-to-end encrypted key-value secrets with fnox, in personal or team namespaces, with interactive or bot-token auth."
---

# FOKS

Store secrets in [FOKS](https://foks.pub), the Federated Open Key Service: an end-to-end encrypted key-value store that you can use on the hosted [foks.app](https://foks.app) or on your own server. Values are encrypted on the client and stay in FOKS; `fnox.toml` holds key paths. The provider reads and writes through the `foks` CLI.

|                     |                                                                   |
| ------------------- | ----------------------------------------------------------------- |
| Config type         | `foks`                                                            |
| Storage             | Remote service (end-to-end encrypted)                             |
| Writes (`fnox set`) | Yes                                                               |
| Requires            | [`foks` CLI](https://foks.pub) on `PATH` and a running FOKS agent |

## Quick start

Install the CLI, start the agent and sign up or log in:

```sh
brew install foks   # other platforms: https://foks.pub
foks ctl start
foks signup         # or: foks login
```

Add a provider and store a value through the hidden prompt:

```toml
[providers.foks]
type = "foks"
prefix = "/fnox/"
```

```sh
fnox set DATABASE_URL --provider foks
fnox provider test foks
fnox exec -- npm start
```

`fnox set` writes the key `/fnox/DATABASE_URL` and adds `DATABASE_URL = { provider = "foks", value = "DATABASE_URL" }` to `fnox.toml`.

## Authentication

The `foks` CLI talks to a long-running agent that holds your keys, similar to `ssh-agent`. fnox uses whatever user the agent has active. When the agent is not running or no user is logged in, fnox reports an authentication error and, in an interactive terminal, offers to run `foks ctl start`. Change that command with [`auth_command`](/reference/configuration#auth-command).

### CI {#cicd}

In non-interactive environments, let fnox log in with a FOKS bot token. On the first authentication failure, fnox runs `foks bot use --host <host>` with the bot token, then retries the command. It tries this once per provider per run.

1. Create a [bot token](https://docs.foks.pub) for the user or team the runner acts as.
2. Store it in the CI secret store as `FOKS_BOT_TOKEN`.
3. Set `host` in the provider, or `FOKS_HOST` in the job.

```toml
[providers.foks]
type = "foks"
prefix = "/fnox/"
team = "ops"
host = "foks.app"
```

```yaml
- run: foks ctl start
- run: fnox exec -- ./deploy.sh
  env:
    FOKS_BOT_TOKEN: ${{ secrets.FOKS_BOT_TOKEN }}
```

Without a host, fnox skips the bot login and logs a warning.

## Configuration

| Field       | Required | Default                                      | Description                                                                                                         |
| ----------- | -------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `prefix`    | No       |                                              | Path prepended to every key. Made absolute if you omit the leading `/`.                                             |
| `team`      | No       | Personal namespace                           | FOKS team, passed as `--team`. Reads and writes use that team's namespace.                                          |
| `home`      | No       | `FNOX_FOKS_HOME`, then `FOKS_HOME`           | FOKS home directory, passed as `--home`. Relative paths resolve against the config file that declares the provider. |
| `host`      | No       | `FNOX_FOKS_HOST`, then `FOKS_HOST`           | FOKS server for bot-token login, such as `foks.app`.                                                                |
| `bot_token` | No       | `FNOX_FOKS_BOT_TOKEN`, then `FOKS_BOT_TOKEN` | Bot token for non-interactive login. Prefer the environment variable over committing it.                            |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

## Reference formats

A secret's `value` is a key path. fnox joins it to the provider's `prefix` with a single `/` and makes the result absolute.

| Provider `prefix`  | `value`        | Key fnox reads       |
| ------------------ | -------------- | -------------------- |
| (none)             | `DATABASE_URL` | `/DATABASE_URL`      |
| `/fnox/` or `fnox` | `DATABASE_URL` | `/fnox/DATABASE_URL` |
| `/fnox/`           | `db/primary`   | `/fnox/db/primary`   |

A value that holds JSON can be narrowed with [`json_path`](/reference/configuration#json-path).

`fnox set` overwrites an existing key and creates missing parent directories. The value goes to `foks kv put` on standard input, not on the command line.

## Personal and team secrets

Use one provider instance per namespace to mix personal and team secrets:

```toml
[providers]
me = { type = "foks", prefix = "/fnox/" }
ops = { type = "foks", prefix = "/fnox/", team = "ops" }

[secrets]
GITHUB_TOKEN = { provider = "me", value = "github-token" }
DATABASE_URL = { provider = "ops", value = "db/primary" }
```

`GITHUB_TOKEN` comes from your personal namespace. `DATABASE_URL` comes from the `ops` team's namespace, which its members can also read.

## Troubleshooting

### Could not connect to the FOKS agent

Start the agent and check it:

```sh
foks ctl start
foks ctl status
```

### Not logged in, or user is locked

Run `foks login`. For a bot, reload the token with `foks bot use --host <host>` and check that the host matches the server that issued the token.

### Secret not found

List keys to confirm the composed path, adding `--team` when the provider sets one:

```sh
foks kv ls /fnox/
foks kv ls --team ops /fnox/
```

## See also

- [HashiCorp Vault](/providers/vault): a self-hosted alternative.
- [password-store](/providers/password-store): GPG-encrypted files you sync yourself.
- [CI/CD](/guide/ci): supply bot tokens to non-interactive jobs.
