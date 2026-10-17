---
description: "A complete example project: age-encrypted development and staging secrets in git, production secrets in AWS Secrets Manager, CI, and onboarding."
---

# Development to production

This walkthrough builds a setup many teams end up with:

- **Development and staging** secrets are age-encrypted in `fnox.toml`, so cloning the repo is enough to start (given a key).
- **Production** secrets live in AWS Secrets Manager, readable only by deployers and CI.
- The application never knows the difference: it reads `DATABASE_URL` and `JWT_SECRET` everywhere.

If every environment already lives in a vault, [use an existing vault](/guide/existing-vault) instead.

## 1. Development

Follow the [quick start](/guide/quick-start) to create a key and an age provider, adding the public keys of your teammates and a [CI key](/guide/teams#give-ci-its-own-key) to `recipients`. Then:

```toml
#:schema https://fnox.jdx.dev/schema.json
default_provider = "age"

[providers.age]
type = "age"
recipients = ["age1...", "age1...", "age1..."] # you, a teammate, CI

[secrets]
LOG_LEVEL = { default = "debug" }
```

```sh
fnox set DATABASE_URL
fnox set JWT_SECRET
fnox exec -- npm start
```

## 2. Staging

Write staging values into the `staging` profile:

```sh
fnox set DATABASE_URL --profile staging
fnox set JWT_SECRET --profile staging
fnox exec --profile staging -- npm start
```

They go under `[profiles.staging.secrets]`. Staging inherits the age provider and `LOG_LEVEL` from the top level.

## 3. Production

Create the production secrets in AWS (named `myapp/database-url` and `myapp/jwt-secret` here) with your usual tooling, then reference them:

```toml
[profiles.production.providers.aws]
type = "aws-sm"
region = "us-east-1"
prefix = "myapp/"

[profiles.production.secrets]
LOG_LEVEL = { default = "info" }
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }
JWT_SECRET = { provider = "aws", value = "jwt-secret", if_missing = "error" }
```

`fnox.toml` contains only names here. Who can read production is decided by AWS IAM, not by the age recipients. With AWS credentials:

```sh
fnox check --all --profile production
fnox exec --profile production -- ./deploy.sh
```

Add `--no-defaults` if production must not inherit any top-level secret it doesn't override.

## 4. Ignore personal files

```sh
printf 'fnox.local.toml\n.fnox.local.toml\n' >> .gitignore
git add fnox.toml .gitignore
git commit -m "chore: add fnox"
```

Developers can now override values in `fnox.local.toml`, such as pointing `DATABASE_URL` at a local database.

## 5. CI

Tests use the development values with the CI age key. Deploys use the production profile with an AWS role:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: jdx/mise-action@v5
      - run: fnox exec --if-missing error -- npm test
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
          FNOX_NON_INTERACTIVE: "true"

  deploy:
    needs: test
    runs-on: ubuntu-latest
    environment: production
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v7
      - uses: jdx/mise-action@v5
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          aws-region: us-east-1
      - run: fnox exec --profile production --if-missing error -- ./deploy.sh
        env:
          FNOX_NON_INTERACTIVE: "true"
```

`jdx/mise-action` installs fnox if it is in `mise.toml` (`mise use fnox`). See [CI/CD](/guide/ci) for other providers and log masking.

## 6. Onboarding

A new teammate:

1. Installs fnox and creates a key: `mkdir -p ~/.config/fnox && age-keygen -o ~/.config/fnox/age.txt`.
2. Sends you the public key.

You add it to `recipients`, run `fnox reencrypt --provider age` for the default and staging profiles, and commit. They pull, run `fnox check --all`, and they're set. Grant AWS access separately if they deploy.

When someone leaves, remove their key, re-encrypt, and rotate the development and staging secrets. See [team setup](/guide/teams#remove-someone).

## See also

- [Profiles](/guide/profiles): inheritance and stacking.
- [AWS Secrets Manager](/providers/aws-sm): permissions and reference formats.
- [Shell integration](/guide/shell-integration): load development secrets on `cd`.
