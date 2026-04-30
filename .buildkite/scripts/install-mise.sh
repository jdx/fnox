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
# cluster UI).
if [[ -z ${GITHUB_TOKEN:-} ]] && command -v buildkite-agent >/dev/null 2>&1; then
	echo "~~~ Fetching GITHUB_TOKEN from Buildkite cluster secrets"
	if token=$(buildkite-agent secret get GITHUB_TOKEN 2>&1); then
		export GITHUB_TOKEN="$token"
		echo "GITHUB_TOKEN loaded from cluster secret store"
	else
		echo "buildkite-agent secret get GITHUB_TOKEN failed:"
		echo "$token"
		echo "Create the secret with: buildkite-agent secret create GITHUB_TOKEN <token>"
		echo "  (or via the Buildkite cluster UI under Secrets)"
	fi
fi

if ! command -v mise >/dev/null 2>&1; then
	curl -fsSL https://mise.run | sh
fi

# Bats tests + cargo runs need to trust the project's mise.toml without
# the interactive prompt mise emits on first run.
mise trust --all >/dev/null 2>&1 || true
