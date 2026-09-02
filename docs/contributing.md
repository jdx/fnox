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

fnox uses [hk](https://hk.jdx.dev) for linting and formatting. Run the checks
before opening a PR:

```sh
hk check --all
hk fix --all
```

fnox also exposes these as the wrapper tasks `mise run lint` and
`mise run lint-fix`; prefer those.

## Commit and PR Titles

Use Conventional Commits for commit messages and PR titles. Examples:

- `fix: handle missing config file`
- `docs: clarify installation steps`
- `feat: add quiet output mode`

## Testing

Run the relevant tests for the code you changed, and the full CI-style task when
practical:

```sh
mise run test:cargo   # Rust unit and integration tests
mise run test:bats    # End-to-end CLI tests (builds first)
mise run test         # Both
mise run ci           # Build, test, and lint
```

Run `mise tasks` or check `mise.toml` for the complete list.

## Development

Install project tools with mise, then build:

```sh
mise install
mise run build
```

Run the lint and test tasks above before opening a PR. See
[CONTRIBUTING.md](https://github.com/jdx/fnox/blob/main/CONTRIBUTING.md) in the
repository for notes on the mbx build cache.
