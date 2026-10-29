---
description: "Store whole files such as ~/.kube/config as encrypted secrets keyed by their path, edit them in place, and write them back to disk with mode 0600."
---

# Secret files

Some secrets are files that must exist at a fixed path outside `fnox exec`: `~/.kube/config`, `~/.aws/credentials`, `~/.npmrc`. A file stored this way is declared by the path it belongs at, encrypted by the same providers as any secret, and never placed in the environment.

## Store a file

```sh
fnox set --file ~/.kube/config
```

This reads the file and records it in `[files]` of your [global config](/reference/configuration#files-and-load-order), encrypted with the provider the entry already uses, else `default_provider`:

```toml
# ~/.config/fnox/config.toml
[files]
"~/.kube/config" = { provider = "age", value = "YWdl..." } # ciphertext, abbreviated
```

To store content from somewhere else, name it with `--from-file`:

```sh
fnox set --file ~/.aws/credentials --from-file ./credentials.new
```

fnox keeps the bytes exactly, final newline included, so what you store is what `fnox files write` produces. The content must be UTF-8 text.

`--provider` picks another provider. For a remote provider such as 1Password, the content is written there and the config records its key; `--key-name` sets that key (the default is derived from the path, such as `kube-config`). The `plain` provider is refused, since it would leave the file readable in the config.

## Read, edit, and remove

```sh
fnox get --file ~/.kube/config     # print it, without adding a newline
fnox edit --file ~/.kube/config    # open it in $EDITOR and store the change
fnox remove --file ~/.kube/config  # drop the entry
```

`edit` stores the change with the file's own provider, in the profile that declares it. `remove` deletes the entry only; the file on disk, any `source` file, and a value stored at a remote provider stay where they are.

`~/.kube/config` and `/home/me/.kube/config` name the same file, so use whichever your shell expands to.

## Write files to disk

```sh
fnox files write
```

writes every file of the active profiles to its path with mode `0600`, creating missing directories. A file whose content already matches is left alone, and its mode is corrected. Pass paths to write only those files, or `--dry-run` to list what would be written.

fnox resolves every file before writing any of them, so a failing provider does not leave the others half-done. Each file is written to a temporary file in the same directory and renamed into place, so a reader never sees a partial file, and a symlink at the path is replaced rather than written through.

`fnox files` lists the files, their profiles, and their providers without decrypting anything.

## Keep ciphertext out of the config

A large file makes the config noisy to review. `--source` keeps the stored content in a separate file next to the config:

```sh
fnox set --file ~/.kube/config --source files/kube-config.age
```

```toml
[files]
"~/.kube/config" = { provider = "age", source = "files/kube-config.age" }
```

The path is relative to the config's directory and cannot leave it. Later `set` and `edit` commands keep writing to the same file. If a dotfiles manager such as stow links the config or an entry's source file into the config directory, fnox follows the link and writes through it, so the link is kept. The first `set --source` refuses a file or link already at that path, so create the link after it.

## Profiles

Files follow [profiles](/guide/profiles) like secrets do. Declare them under `[profiles.work.files]` and select them with `-P work`; a profile's entry overrides the top-level entry for the same path, and `--no-defaults` skips the top-level ones.

```sh
fnox -P work set --file ~/.kube/config
fnox -P work files write
```

## Cache a file locally

A file stored at a slow remote provider such as 1Password can be cached under a local encryption provider, like secrets. `fnox sync` fetches each file once, encrypts it with the target provider, and records the ciphertext in the entry's `sync` field:

```sh
fnox sync -p sync-age
```

```toml
[files]
"~/.kube/config" = { provider = "1password", value = "kube-config", sync = { provider = "sync-age", value = "YWdl..." } }
```

`fnox get --file`, `fnox files write`, and `fnox edit --file` then decrypt the copy instead of calling 1Password. The original reference stays in place, so run `fnox sync` again after the file changes at its source. `fnox set --file`, `fnox edit --file`, and `fnox reencrypt` store new content and drop the old cache.

The cache is written to the config that declares the entry, always the global config. The target provider must be an encryption provider of the global config. `--source`, `--filter`, and path arguments such as `fnox sync ~/.kube/config` narrow which files are cached; see [local sync cache](/guide/sync).

## Rotate encryption

`fnox reencrypt` re-encrypts files along with secrets, writing the new ciphertext back to the `value` or `source` that holds it. Name secrets as arguments to leave the files out.

## Why only the global config

A path is a place fnox writes. If a project's `fnox.toml` could declare files, cloning a repository and running `fnox files write` could overwrite `~/.ssh/authorized_keys` or `~/.bashrc`. So `[files]` is accepted only in the global config, and a project file that declares it is rejected.

## See also

- [`[files]` reference](/reference/configuration#files)
- [`fnox files`](/cli/files), [`fnox set`](/cli/set), [`fnox get`](/cli/get), [`fnox edit`](/cli/edit)
