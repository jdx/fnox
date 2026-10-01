---
description: "Set up a fnox development checkout, run checks, edit documentation, and prepare a contribution for review."
---

# Contributing

::: danger AI replies to Discussions and Issues are restricted
You may only use AI to reply to a [Discussion](https://github.com/jdx/fnox/discussions) or [Issue](https://github.com/jdx/fnox/issues) if you
created it, you opened a PR that fixes it, or you have already had a contribution merged into
fnox. Everyone else is not allowed to use AI to reply. This is a growing problem, and **doing it is
an instant ban across all of jdx's projects.**

This includes raw, lightly edited, reviewed, and disclosed model output. Adding an "AI-assisted"
footer does not make an AI reply acceptable on its own. If you are running an agent, make sure it
does not post to threads you are not allowed to reply to, and never let it sweep through many
threads at once.
:::

Using AI to help write and file your own Discussion or Issue is fine. If you are allowed to use AI to
reply, review and verify anything before posting it, and disclose that AI contributed.

Contributions should solve a clear problem within fnox's scope. For a substantial change, discuss the direction first in [GitHub Discussions](https://github.com/jdx/fnox/discussions) or [Discord](https://discord.gg/UBa7pJUN7Z). Small, obvious fixes can go straight to a pull request.

## What to expect in review

CI must pass and automated review comments must be addressed before maintainer review. Explain the problem, the resulting behavior, and how you verified it.

fnox has a deliberate scope and design direction. A change may be declined because it does not fit, introduces too much complexity, or is not ready for review. Maintainer time is limited across many projects, so a rejection may be brief and detailed coaching may not be available.

## Development setup

Clone the repository, install its tools, and build the debug binary:

```sh
git clone https://github.com/jdx/fnox
cd fnox
mise install
mise run build
```

Use the repository's mise tasks so tool versions and the Cargo build wrapper are consistent.

## Checks

```sh
mise run test:cargo
mise run build
mise run test:bats -- test/init.bats
mise run lint
```

Build before running Bats tests; `test:bats` uses the existing binary. Use `mise run test` for both test suites and `mise run ci` for the full set of build, test, and lint tasks. Some provider tests require credentials or a local service; see the [test guide](https://github.com/jdx/fnox/blob/main/test/README.md).

Run `mise run lint-fix` to apply formatting fixes. Run tests appropriate to the behavior you changed.

## Documentation changes

```sh
aube install
aube run docs:dev
aube run docs:build
```

Review the affected page in a browser, including narrow layouts and both themes when changing styles. The production build checks internal links, anchors, and social metadata.

CLI pages are generated. Update their source help or the maintained examples, then regenerate them; see the [documentation contributor guide](https://github.com/jdx/fnox/blob/main/docs/README.md#generated-reference).

## Commit and pull request titles

Use Conventional Commits with a lowercase, imperative description:

- `fix(aws-sm): handle missing secrets`
- `docs: clarify installation steps`
- `feat(exec): add a command option`

Follow the [repository conventions](https://github.com/jdx/fnox/blob/main/AGENTS.md) for accepted types and scopes, MSRV, dependency changes, and AI assistance disclosure. Keep dependency updates focused and do not raise the MSRV to accommodate a dependency.
