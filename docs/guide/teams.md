---
description: "Share fnox secrets with a team: add and remove people, re-encrypt for new recipients, rotate after someone leaves, and give CI its own identity."
---

# Team setup

How you share secrets depends on where they live:

- **Vault references** (1Password, AWS, Vault, …): access is managed in the vault. fnox has nothing to share; each person reads with their own login.
- **Encrypted in `fnox.toml`** (age): access is the list of public keys, called _recipients_, that each value is encrypted to. Changing who has access means changing that list and re-encrypting.

Most of this page is about the second case.

## Encrypt to everyone

Each person keeps a private key on their machine and shares only the public part. An existing SSH key works too:

```sh
age-keygen -y ~/.config/fnox/age.txt   # age public key (age1...)
cat ~/.ssh/id_ed25519.pub              # or an SSH public key
```

List every public key in the provider, with a comment saying whose it is:

```toml
[providers.age]
type = "age"
recipients = [
  "age1...",          # alice
  "ssh-ed25519 AAAA...", # bob
  "age1...",          # ci (see below)
]
```

Every value `fnox set` writes from now on can be decrypted by any of them. Each person's fnox finds their private key automatically at `~/.config/fnox/age.txt`, or wherever the provider's [`key_file`](/providers/age#set-decryption-key) or `FNOX_AGE_KEY` points.

## Add someone

1. They create a key and send you the public part.
2. You add it to `recipients`.
3. You re-encrypt existing secrets, since they were encrypted before the new key was listed. Do it for each profile that has age secrets:

   ```sh
   fnox reencrypt --provider age --dry-run
   fnox reencrypt --provider age
   fnox reencrypt --provider age --profile staging
   ```

4. Commit `fnox.toml`. They pull and run `fnox check --all`.

Only someone who can already decrypt can re-encrypt.

## Remove someone

Remove their key from `recipients` and re-encrypt as above. That stops them decrypting **new** ciphertext, but they can still decrypt old ciphertext from git history, and they may have copies of the values. Rotate every secret they could read: change it at its source, then store the new value with `fnox set`.

This is the main trade-off of encrypting secrets into git. If people come and go often, keep the secrets in a vault, where removing access is immediate.

## Give CI its own key

Create a dedicated key for CI rather than reusing a person's:

```sh
age-keygen -o ci-age.txt   # prints the public key
```

Add the public key to `recipients` and re-encrypt. Store the contents of `ci-age.txt` in your CI secret store as `FNOX_AGE_KEY`, then delete the local file. See [CI/CD](/guide/ci).

## Separate access to production

[Profiles](/guide/profiles) choose configuration; they don't restrict who can decrypt. To keep production away from people who only need development values, give production a different storage boundary:

- reference a production vault or cloud secret manager that only deployers and CI can read, or
- define a second age provider with a smaller recipient list and use it only in the production profile.

```toml
[providers.age-prod]
type = "age"
recipients = ["age1..."] # deployers and CI only

[profiles.production.secrets]
DATABASE_URL = { provider = "age-prod", value = "YWdl..." }
```

## Personal values

Each developer can override anything in a gitignored `fnox.local.toml`, for example a local database. Their [sync cache](/guide/sync) lives there too. See [local overrides](/guide/config-files#local-overrides).

## See also

- [age provider](/providers/age): keys, SSH recipients, and hardware plugins.
- [Use an existing vault](/guide/existing-vault): the vault-based team setup.
- [Development to production](/guide/dev-to-production): a full project with teammates, CI, and production.
