---
description: "The write-only stores fnox push can copy secrets into: GitHub Actions, GitLab CI, Vercel, Cloudflare Workers, Fly.io, Forgejo and HCP Terraform."
---

# Push targets

A push target is a place that needs your secrets but never gives them back, such as CI secrets or a hosting platform's environment variables. Define one under `[targets.<name>]`, list it in a secret's `push` field, and run `fnox push`. See [the push guide](/guide/push) for how pushing works, profiles, and what it protects.

| Target                                            | Config type          | Sets                                        | Through        | Readable afterwards  |
| ------------------------------------------------- | -------------------- | ------------------------------------------- | -------------- | -------------------- |
| [GitHub Actions](/targets/github-actions)         | `github-actions`     | Actions, Dependabot and Codespaces secrets  | `gh` CLI       | No                   |
| [GitLab CI/CD](/targets/gitlab-ci)                | `gitlab-ci`          | Project and group CI/CD variables           | `glab` CLI     | Yes, by maintainers  |
| [Vercel](/targets/vercel)                         | `vercel`             | Project environment variables               | `vercel` CLI   | No, with `sensitive` |
| [Cloudflare Workers](/targets/cloudflare-workers) | `cloudflare-workers` | Worker secrets                              | `wrangler` CLI | No                   |
| [Fly.io](/targets/fly)                            | `fly`                | App secrets                                 | `fly` CLI      | No                   |
| [Forgejo and Gitea](/targets/forgejo-actions)     | `forgejo-actions`    | Repository and organization Actions secrets | REST API       | No                   |
| [HCP Terraform](/targets/hcp-terraform)           | `hcp-terraform`      | Workspace variables                         | REST API       | No, with `sensitive` |

Every target replaces an existing value with the same name. CLI-based targets receive the value on stdin, so it never appears in a process listing, and use whatever login their CLI already has. API-based targets read a token from the environment.

::: warning Experimental
Push targets are new, and their config format may change.
:::
