---
description: "Copy secrets from fnox into write-only stores such as GitHub Actions, Vercel and Fly.io with fnox push, so fnox stays the source of truth."
---

# Push targets

Some places that need your secrets will accept a value but never return it. CI secrets and hosting platforms' environment variables work this way, so fnox can't read from them like a provider. `fnox push` goes the other way: it resolves each secret from its provider and writes the value to the targets listed in that secret's `push` field.

fnox stays the source of truth. When you rotate a key, change it in fnox and run `fnox push` again, instead of updating every dashboard by hand.

fnox can push to GitHub Actions, GitLab CI/CD, Vercel, Cloudflare Workers, Fly.io, Forgejo and Gitea, and HCP Terraform. See the [target catalog](/targets/) for each one's settings.

::: warning Experimental
Push targets are new, and their config format may change.
:::

## Set up

Define a target under `[targets.<name>]`, then list it in the `push` field of each secret that should go there:

```toml
[targets.gh]
type = "github-actions"
repo = "acme/api"

[targets.gh-prod]
type = "github-actions"
repo = "acme/api"
environment = "production"

[secrets]
STRIPE_KEY = { provider = "op", value = "Stripe/secret key", push = ["gh-prod"] }
NPM_TOKEN = { provider = "age", value = "YWdl...", push = ["gh"] }
DATABASE_URL = { provider = "age", value = "YWdl..." } # stays local
```

Preview, then push:

```console
$ fnox push --dry-run
[dry-run] Would push 2 secrets (2 writes):
  STRIPE_KEY → gh-prod (GitHub Actions secret in acme/api, environment production)
  NPM_TOKEN → gh (GitHub Actions secret in acme/api)

$ fnox push
Ready to push 2 secrets (2 writes):
  ...
Continue? [y/N]
y
✓ STRIPE_KEY → gh-prod
✓ NPM_TOKEN → gh
Pushed 2 of 2
```

The name at the target is the fnox key. fnox pushes the value as `fnox get` would return it, after `json_path` and `line` are applied.

Narrow a push with key names and `--target`:

```sh
fnox push STRIPE_KEY            # one secret, all its targets
fnox push --target gh-prod      # every secret that goes to gh-prod
fnox push --force               # no confirmation prompt, for scripts
```

fnox checks every target name and target config before it resolves or pushes anything, so a typo in `push` fails the whole command. If one write fails, fnox keeps going with the rest, then exits non-zero and lists the failures.

## Profiles

Targets layer like providers: a profile can define its own targets or replace a top-level one with the same name. That lets one `push` list send each profile's values to a different place:

```toml
[targets.gh-env]
type = "github-actions"
repo = "acme/api"
environment = "staging"

[profiles.production.targets.gh-env]
type = "github-actions"
repo = "acme/api"
environment = "production"

[secrets]
STRIPE_KEY = { provider = "op", value = "Stripe/test key", push = ["gh-env"] }

[profiles.production.secrets]
STRIPE_KEY = { provider = "op", value = "Stripe/live key", push = ["gh-env"] }
```

`fnox push` sends the test key to the `staging` environment, and `fnox -P production push` sends the live key to `production`. A secret overridden in a profile replaces the whole entry, `push` included.

## What this protects

Pushing from fnox means the value never passes through a terminal, a clipboard, a chat transcript, or a web form, and CLI-based targets receive it on stdin rather than as an argument. It does not make the value unreadable: anyone who can change code that runs with the secret, such as a CI workflow or a deployed app, can print it. Treat a push target as handing the secret to everyone with write access there.
