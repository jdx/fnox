#!/usr/bin/env bash
# Install mise into ~/.local/bin if it isn't already on PATH, then make
# sure ~/.local/bin is on PATH for the rest of the step. Source this from
# the pipeline (`source .buildkite/scripts/install-mise.sh`) so PATH
# changes survive into the next command.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

# mise resolves dozens of tool versions through the GitHub API; without a
# token it hits the unauthenticated rate limit and fails to install.
# Pull GITHUB_TOKEN from the Buildkite cluster secret store if the caller
# hasn't already set it (set up via `buildkite-agent secret create` or the
# cluster UI). Failing to read is non-fatal — mise will warn loudly.
if [[ -z ${GITHUB_TOKEN:-} ]] && command -v buildkite-agent >/dev/null 2>&1; then
	if token=$(buildkite-agent secret get GITHUB_TOKEN 2>/dev/null) && [[ -n $token ]]; then
		export GITHUB_TOKEN="$token"
	fi
fi

if ! command -v mise >/dev/null 2>&1; then
	curl -fsSL https://mise.run | sh
fi

# Bats tests + cargo runs need to trust the project's mise.toml without
# the interactive prompt mise emits on first run.
mise trust --all >/dev/null 2>&1 || true
