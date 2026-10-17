---
description: "Use profiles for development, staging, and production values in one fnox.toml: inherit shared settings, switch providers, compose profiles, and choose where writes go."
---

# Profiles

A profile is a named set of overrides for one environment. The top level of `fnox.toml` is the `default` profile; other profiles inherit everything from it and replace what they need.

```toml
[providers.age]
type = "age"
recipients = ["age1..."]

[secrets]
LOG_LEVEL = { default = "debug" }
DATABASE_URL = { provider = "age", value = "YWdl..." } # development

[profiles.production.providers.aws]
type = "aws-sm"
region = "us-east-1"
prefix = "myapp/"

[profiles.production.secrets]
LOG_LEVEL = { default = "info" }
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }
```

In `production`, `DATABASE_URL` comes from AWS Secrets Manager and `LOG_LEVEL` is `info`. Anything production doesn't override, including the `age` provider, is inherited.

## Select a profile

```sh
fnox exec --profile production -- ./deploy.sh   # or -P production
export FNOX_PROFILE=production                  # for the whole session
```

With [shell integration](/guide/shell-integration), changing `FNOX_PROFILE` reloads the shell's secrets at the next prompt.

`fnox profiles` lists the profiles defined in the current config.

## Write to a profile

Write commands (`set`, `remove`, `import`, `sync`, `provider add`, `provider remove`) target the selected profile:

```sh
fnox set DATABASE_URL --profile staging --provider age
```

This writes under `[profiles.staging.secrets]`.

## Leave out top-level secrets

By default every profile includes the top-level secrets. `--no-defaults` (or `FNOX_NO_DEFAULTS=true`) drops them, so only the selected profile's own secrets are used. Top-level providers are still available.

```sh
fnox exec --profile production --no-defaults -- ./deploy.sh
```

## Inherit from other profiles

A profile can build on other profiles with `inherits`. They apply in order, then the profile's own settings, so later entries win:

```toml
[profiles.openai.secrets]
OPENAI_API_KEY = { provider = "age", value = "YWdl..." }

[profiles.local-db.secrets]
DATABASE_URL = { default = "postgresql://localhost/app" }

[profiles.api]
inherits = ["openai", "local-db"]
```

```sh
fnox -P api exec -- ./api
```

Inheritance covers secrets, providers, lease backends, and `default_provider`. Nesting is allowed; cycles and unknown profile names are configuration errors.

## Stack profiles on the command line

You can also activate several profiles at once. They layer on top of the top-level config in the order given:

```sh
fnox -P aws -P prod exec -- ./app
fnox -P aws,prod exec -- ./app
FNOX_PROFILE=aws,prod fnox exec -- ./app
```

This is useful when concerns are split: `aws` holds provider settings, `prod` holds production secret references, `ci` adds CI-only values.

When more than one profile is active, write commands need to know which one to change:

```sh
fnox -P aws,prod --write-profile prod set DATABASE_URL
```

## Profiles in separate files

Instead of `[profiles.staging]` sections, you can put a profile's settings in `fnox.staging.toml` next to `fnox.toml`. It is loaded only when `staging` is selected. See [config files](/guide/config-files#profile-files).

## A profile is not an access boundary

Profiles choose configuration, not who can read it. Anyone who can decrypt the top-level age secrets can decrypt staging secrets encrypted to the same recipients. To restrict production, store it somewhere only production identities can read, such as a separate vault, a cloud secret manager, or an age provider with different recipients.

## See also

- [Config files](/guide/config-files): how files and directories layer.
- [Development to production](/guide/dev-to-production): a complete multi-environment setup.
- [Configuration reference](/reference/configuration#profile-configuration): every profile field.
