---
description: "Use fnox as a git credential helper so git, cargo, and go authenticate with short-lived GitHub and GitLab tokens instead of a personal access token on disk."
---

# Git credential helper

`fnox git-credential` implements git's [credential helper protocol](https://git-scm.com/docs/gitcredentials). When git, or a tool that shells out to git such as cargo or go, needs a password for a GitHub or GitLab remote, fnox hands it a short-lived token from a [lease backend](/guide/leases). No personal access token is stored on disk.

It serves tokens from these lease backends:

| Backend                                | Git host                                                                                                     | Username sent    |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------- |
| [`github-app`](/leases/github-app)     | `github.com`, or the git host of `api_base` for GitHub Enterprise (`api.acme.ghe.com` serves `acme.ghe.com`) | `x-access-token` |
| [`github-oauth`](/leases/github-oauth) | `github.com`, or the git host of `api_base` for GitHub Enterprise (`api.acme.ghe.com` serves `acme.ghe.com`) | `x-access-token` |
| [`gitlab`](/leases/gitlab)             | The host of `url` (`gitlab.com` by default)                                                                  | `oauth2`         |

## Set up

Define a lease backend, then register the helper with git:

```toml
# fnox.toml
[leases.github]
type = "github-oauth"
client_id = "Iv1.0123456789abcdef"
```

```sh
git config --global credential.helper '!fnox git-credential'
```

Now `git clone https://github.com/you/repo` asks fnox for a token. fnox reuses a cached lease while it is valid, and creates a new one when it is not.

git runs the helper from the repository's directory, so that project's `fnox.toml` applies. To use one backend everywhere, define it in `~/.config/fnox/config.toml`.

## Choosing a backend

fnox picks the backend whose host matches the request. If several backends serve the same host, the last one in the config wins; pass `--backend` to pick one:

```sh
git config credential.https://github.com.helper '!fnox git-credential --backend work'
```

When no backend serves the host, or no fnox config is found, fnox prints nothing and exits 0, so git moves on to its next helper. `store` and `erase` do nothing, because leases expire on their own.

fnox returns tokens only for HTTPS requests, or plain HTTP to `localhost`, `127.0.0.1` or `::1`, so a token never crosses a network in cleartext.

## Try it by hand

```sh
printf 'protocol=https\nhost=github.com\n\n' | fnox git-credential get
```

```text
username=x-access-token
password=ghu_...
```

The output contains a real token; keep it out of logs.
