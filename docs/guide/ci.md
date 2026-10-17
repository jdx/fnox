---
description: "Use fnox in GitHub Actions and other CI systems: install it, authenticate the runner, fail fast on missing secrets, mask values in logs, and handle forks."
---

# CI/CD

In CI you run the same `fnox exec` command as on your laptop. The only difference is how the runner authenticates: instead of a person's key or vault login, it gets one credential from the CI secret store, and fnox reads everything else through it.

```yaml
- run: fnox exec --if-missing error -- npm test
```

## 1. Install fnox

With [mise](https://mise.jdx.dev), add fnox to the project's `mise.toml` (`mise use fnox`) and install everything in one step:

```yaml
- uses: jdx/mise-action@v5
```

Without mise, download a binary from [GitHub Releases](https://github.com/jdx/fnox/releases) or run `cargo install fnox --locked`. Install any CLI your provider needs, such as `op` for 1Password.

## 2. Give the runner one credential

| Secrets live in                                                   | Give CI                                                                      | As                                    |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------- |
| [age](/providers/age), encrypted in `fnox.toml`                   | A CI-only age private key, listed in `recipients`                            | `FNOX_AGE_KEY`                        |
| [1Password](/providers/1password)                                 | A service account token                                                      | `OP_SERVICE_ACCOUNT_TOKEN`            |
| [AWS](/providers/aws-sm) Secrets Manager, Parameter Store, or KMS | A role, ideally through OIDC                                                 | The standard AWS credential variables |
| [Google Cloud](/providers/gcp-sm) or [Azure](/providers/azure-sm) | Workload identity, or a service principal                                    | The standard SDK variables            |
| Other providers                                                   | Whatever the [provider page](/providers/overview) lists under Authentication |                                       |

### age

Create a key just for CI, add its public key to `recipients`, and [re-encrypt](/guide/teams#add-someone). Then store the private key (the whole `AGE-SECRET-KEY-1...` line) as a CI secret:

```yaml
- run: fnox exec -- npm test
  env:
    FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
```

### 1Password

```yaml
- run: fnox exec -- npm test
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
```

Scope the service account to the vaults the job needs.

### AWS with OIDC

No stored credential at all: GitHub exchanges a short-lived token for a role.

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/ci-deploy
      aws-region: us-east-1
  - run: fnox exec --profile production -- ./deploy.sh
```

## 3. Fail fast

Two settings make CI failures obvious instead of confusing:

- **`--if-missing error`** stops before your command runs if any secret can't be resolved, instead of starting it with variables missing. Or set `FNOX_IF_MISSING=error` for the whole job. See [missing secrets](/guide/missing-secrets).
- **`--non-interactive`** (or `FNOX_NON_INTERACTIVE=true`) means fnox never tries to prompt or open a browser. A provider that needs an interactive login fails immediately with an error.

```yaml
env:
  FNOX_NON_INTERACTIVE: "true"
  FNOX_IF_MISSING: error
```

Run `fnox check --all` as an early step to verify access without printing values.

## 4. Keep values out of logs

CI systems mask the secrets you configure in them, but not values fnox reads from elsewhere. If a command might print a secret, mask everything fnox resolves for the rest of the job. On GitHub Actions:

```yaml
- run: fnox ci-redact
```

This prints an `::add-mask::` command for each resolved value. Multi-line values can't be masked this way; fnox warns about them. Other CI systems don't support masking at run time, so configure masked variables in their settings instead.

## Environments and profiles

Select a [profile](/guide/profiles) per job, and pair it with the CI system's own protection rules, such as GitHub environments with required reviewers:

```yaml
jobs:
  deploy:
    environment: production
    steps:
      - uses: actions/checkout@v7
      - uses: jdx/mise-action@v5
      - run: fnox exec --profile production --if-missing error -- ./deploy.sh
        env:
          FNOX_NON_INTERACTIVE: "true"
```

## Pull requests from forks

Workflows triggered by `pull_request` events from forks don't receive repository secrets, so fnox can't authenticate. If your tests can run without some secrets, let them be skipped:

```yaml
- run: fnox exec -- npm test
  env:
    FNOX_IF_MISSING: ignore
```

Mark secrets the tests truly need with `if_missing = "error"` in `fnox.toml`. The environment variable overrides that, so use it only in the fork-safe job.

::: warning
`pull_request_target` workflows do receive repository secrets, even for forks. Never check out and run fork code in a `pull_request_target` job that has fnox credentials: the fork's code could read every secret fnox resolves.
:::

## Other CI systems

Nothing in fnox is GitHub-specific. In GitLab CI, CircleCI, Buildkite, or anything else: install the binary, expose the one credential as an environment variable, and run `fnox exec`.

```yaml
# .gitlab-ci.yml
test:
  variables:
    FNOX_NON_INTERACTIVE: "true"
  script:
    - fnox exec --if-missing error -- npm test # FNOX_AGE_KEY set as a masked CI/CD variable
```

## Caches in CI

You usually don't need the [sync cache](/guide/sync) or the [daemon](/guide/daemon) on ephemeral runners: each job resolves once and exits. For many short `fnox` calls in one long job, the daemon can help.

## See also

- [Team setup](/guide/teams): give CI its own age key.
- [Development to production](/guide/dev-to-production): a complete example with a deploy job.
- [Credential leases](/guide/leases): mint short-lived cloud credentials inside the job.
