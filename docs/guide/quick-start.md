---
description: "Encrypt your first secret with age, commit it safely, and run a command with it. Takes about five minutes and needs no cloud account."
---

# Quick start

In this walkthrough you encrypt a secret into `fnox.toml` with [age](https://age-encryption.org), then run a command that receives it as an environment variable. Everything stays on your machine; no account or vault is needed.

Already using 1Password, Bitwarden, AWS, or another vault? Follow [use an existing vault](/guide/existing-vault) instead.

## 1. Install fnox and age

```sh
mise use -g fnox age
```

See [installation](/guide/installation) for other methods. fnox does its own encryption; you only need age for its `age-keygen` command.

## 2. Create a key

```sh
mkdir -p ~/.config/fnox
age-keygen -o ~/.config/fnox/age.txt
```

`age-keygen` prints your **public key**, which starts with `age1`. Copy it. (If you already have `age.txt`, print the public key with `age-keygen -y ~/.config/fnox/age.txt`.)

`age.txt` is your **private key**. fnox reads it from this location automatically. Back it up and never commit it: anyone with this file can decrypt your secrets.

## 3. Configure the project

In your project directory:

```sh
fnox init --skip-wizard
```

Open the new `fnox.toml` and replace its contents with this, pasting your public key:

```toml
#:schema https://fnox.jdx.dev/schema.json
default_provider = "age"

[providers.age]
type = "age"
recipients = ["age1..."] # your public key
```

This defines one provider named `age` and makes it the default for new secrets. The `#:schema` line gives editors completion and validation.

## 4. Store a secret

```sh
fnox set DATABASE_URL
```

Type a value such as `postgresql://localhost/mydb` at the hidden prompt. fnox encrypts it and adds it to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "YWdl..." } # ciphertext, abbreviated
```

To create a new random secret instead of typing one, use `--generate`:

```sh
fnox set API_TOKEN --generate                 # 32 URL-safe characters
fnox set SESSION_KEY --generate --generate-type hex --length 64
```

The value comes from the operating system's random number generator, is stored with the same provider as any other `fnox set`, and is not printed unless you add `--show`. `--generate-type` accepts `password` (default), `hex`, `base64` and `uuid`; `--length` counts output characters (1 to 4096; `base64` cannot use a length that is 1 more than a multiple of 4, such as 5 or 9). An existing secret is only replaced with `--force`.

Check that fnox can decrypt everything, without printing any values:

```sh
fnox check --all
```

## 5. Run a command

```sh
fnox exec -- npm start
```

`npm start` runs with `DATABASE_URL` in its environment. Your shell is unchanged. Everything after `--` is the command; fnox options go before it.

To confirm the variable arrives without printing it:

```sh
fnox exec -- sh -c 'test -n "$DATABASE_URL" && echo "DATABASE_URL is set"'
```

When you need the value itself, `fnox get DATABASE_URL` prints it.

## 6. Commit

`fnox.toml` now contains only ciphertext and your public key, so it is safe to commit. Ignore the files that hold personal overrides:

```sh
printf 'fnox.local.toml\n.fnox.local.toml\n' >> .gitignore
git add fnox.toml .gitignore
git commit -m "chore: add fnox"
```

## Next

- **Load secrets automatically** when you `cd` into the project: [shell integration](/guide/shell-integration).
- **Share with your team** by adding their public keys: [team setup](/guide/teams).
- **Use different values** for staging and production: [profiles](/guide/profiles).
- **Use secrets in CI**: [CI/CD](/guide/ci).
