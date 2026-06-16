# Contributing

Thank you for your interest in contributing to fnox.

## Contribution Expectations

Before opening a PR, unless it is something obvious, consider creating a
discussion or mentioning what you plan to do in
[Discord](https://discord.gg/UBa7pJUN7Z). The important part is to settle the
direction before much review happens. fnox has a specific scope and design
taste. I am comfortable saying no to changes that do not clearly fit.

Before I review a PR, CI must be passing and all automated AI review comments
must be addressed. If those are still open, assume I will wait to look at the
PR.

If I am on the fence about a contribution, I will probably reject it for that
reason alone. If I did not do this, fnox would suffer from feature bloat. I
may also reject a PR if the quality is poor enough that I do not have confidence
the contributor can get it across the finish line. I do not have time to coach
contributors.

I get hundreds of PRs per week across my projects, so I do not have time to
respond to every PR with detailed context. A rejection may be brief.

## Code Style

All of these repos use [hk](https://hk.jdx.dev) for linting and formatting.
Run the checks before opening a PR:

```sh
hk check --all
hk fix --all
```

Some repos also expose wrapper tasks such as `mise run lint` and
`mise run lint-fix`; prefer those when they exist.

## Commit and PR Titles

Use Conventional Commits for commit messages and PR titles. Examples:

- `fix: handle missing config file`
- `docs: clarify installation steps`
- `feat: add quiet output mode`

## Testing

Testing differs by project. Run the relevant tests for the code you changed and
the repo's CI-style task when practical. Check `mise tasks`, `mise.toml`,
and existing README/docs for the exact commands.

## Development

Install project tools with mise:

```sh
mise install
```

Run the checks listed in the repository before opening a PR.
