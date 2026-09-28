---
description: "Encrypt your first secret with age, check access, and run an application with fnox. No cloud account required."
---

# Quick start

Store your first secret with age encryption, then make it available to a command. This walkthrough uses a local key file and needs no cloud account.

Already have a vault? Use [1Password with a local cache](/guide/golden-path), or choose another [provider](/providers/overview).

## 1. Install fnox and age

With [mise](https://mise.jdx.dev):

```sh
mise use -g fnox age
fnox --version
```

See [installation](/guide/installation) for other fnox installation methods. The age CLI supplies `age-keygen`; fnox handles encryption itself.

## 2. Create your encryption key

```sh
mkdir -p ~/.config/fnox
age-keygen -o ~/.config/fnox/age.txt
age-keygen -y ~/.config/fnox/age.txt
```

The last command prints your public recipient, beginning with `age1`. Copy it for the next step. If you already have `age.txt`, reuse it and run only the last command.

Keep `age.txt` private and back it up. The public recipient can go in git; the private key file cannot. fnox automatically reads `age.txt` from its [configuration directory](/reference/environment#fnox-config-dir). If you use a different directory, set the provider's [`key_file`](/providers/age#configuration).

## 3. Configure the project

From your project directory:

```sh
fnox init --skip-wizard
```

Edit the new `fnox.toml` to contain the following, replacing `age1...` with the public recipient you copied:

```toml
#:schema https://fnox.jdx.dev/schema.json
default_provider = "age"

[providers.age]
type = "age"
recipients = ["age1..."] # Replace with your public recipient
```

`--skip-wizard` creates an empty configuration. These provider settings are what enable encryption; initialization alone does not encrypt secrets.

## 4. Store and check a secret

```sh
fnox set DATABASE_URL
```

At the hidden prompt, enter a value such as `postgresql://localhost/mydb`. fnox uses `default_provider = "age"` and writes encrypted ciphertext into `fnox.toml`.

```sh
# Verify that configured secrets can be resolved
fnox check --all

# Inspect names and providers without displaying resolved values
fnox list
```

Use `fnox get DATABASE_URL` when you need the value itself. It prints the decrypted secret to stdout.

## 5. Run a command

```sh
fnox exec -- npm start
# Or:
fnox exec -- python app.py
```

The command receives `DATABASE_URL` as an environment variable. Your parent shell is unchanged. To verify injection without an application or printing the value:

```sh
fnox exec -- sh -c 'test -n "$DATABASE_URL" && printf "Database secret is available\n"'
```

Put fnox options before `--`; everything after it belongs to the command.

## 6. Commit the configuration

Add these entries to your existing `.gitignore`:

```text
fnox.local.toml
.fnox.local.toml
.env
```

Review `fnox.toml`, then commit it with `.gitignore`. The age secret's `value` is ciphertext. Any `default` values remain plaintext, so reserve them for non-sensitive configuration.

## Where to go next

- [Shell integration](/guide/shell-integration): load secrets automatically when you enter a project.
- [Profiles](/guide/profiles): use separate development, staging, and production values.
- [Age team setup](/providers/age#team-workflow): add teammates and re-encrypt for their keys.
- [Troubleshooting](/guide/troubleshooting): diagnose configuration and authentication problems.
