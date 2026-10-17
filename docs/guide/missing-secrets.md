---
description: "Decide whether a secret that can't be resolved fails the command, prints a warning, or is skipped, and supply fallback defaults."
---

# Missing secrets

When fnox can't produce a value for a secret (the provider has no such item, access is denied, the key is missing), the secret's `if_missing` policy decides what happens:

| `if_missing`       | Effect                                                   | Use for                                         |
| ------------------ | -------------------------------------------------------- | ----------------------------------------------- |
| `"error"`          | The command fails before it starts                       | Secrets the program can't run without           |
| `"warn"` (default) | fnox prints a warning and continues without the variable | Most secrets during development                 |
| `"ignore"`         | fnox continues silently                                  | Truly optional values, such as an analytics key |

```toml
if_missing = "error" # project-wide default

[secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }                       # error
SENTRY_DSN = { provider = "aws", value = "sentry-dsn", if_missing = "ignore" }    # optional
```

The policy applies to commands that resolve many secrets at once: `exec`, `export`, `check`, and shell integration. `fnox get KEY` always reports an error if it can't produce that one value.

## Fall back to a default

A `default` is tried before a secret counts as missing, including when the provider lookup fails:

```toml
[secrets]
REDIS_URL = { provider = "aws", value = "redis-url", default = "redis://localhost:6379" }
```

Defaults are plaintext. Use them for non-sensitive values and local development fallbacks, never for real credentials.

## Override at run time

The first of these that is set wins:

1. `--if-missing <policy>` on the command line
2. `FNOX_IF_MISSING` environment variable
3. `if_missing` on the secret
4. Top-level `if_missing` in the config
5. `FNOX_IF_MISSING_DEFAULT` environment variable
6. `warn`

Because the command-line flag and `FNOX_IF_MISSING` beat the config, they're the way to make one run stricter or looser:

```sh
fnox exec --if-missing error -- ./deploy.sh   # nothing may be missing
FNOX_IF_MISSING=ignore fnox exec -- npm test  # e.g. a fork without secret access
```

`FNOX_IF_MISSING_DEFAULT` sits below the config: it changes the fallback for secrets that set no policy, while respecting explicit ones. Setting `FNOX_IF_MISSING_DEFAULT=error` on a CI runner makes unconfigured secrets strict without overriding secrets marked `ignore`.

## Check before you run

```sh
fnox check          # secrets with if_missing = "error"
fnox check --all    # every secret, including warn and ignore
```

Neither prints values.

## See also

- [CI/CD](/guide/ci): strict deploys and pull requests from forks.
- [How fnox works](/guide/how-it-works#resolution-order): the full resolution order.
- [Configuration reference](/reference/configuration#if-missing): the `if_missing` field.
