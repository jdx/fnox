#!/usr/bin/env bash
# Install mise into ~/.local/bin if it isn't already on PATH, then make
# sure ~/.local/bin is on PATH for the rest of the step. Source this from
# the pipeline (`source .buildkite/scripts/install-mise.sh`) so PATH
# changes survive into the next command.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

# mise.lock pins every tool's version + download URL + checksum, so
# `mise install` shouldn't hit the GitHub API at all. If the caller
# already exports GITHUB_TOKEN it's still used for any unforeseen
# fallbacks; otherwise we let mise run unauthenticated.

if ! command -v mise >/dev/null 2>&1; then
	# Retry + HTTP/1.1 to dodge the macOS-side HTTP/2 framing flakes that
	# bit build #13.
	curl --retry 5 --retry-delay 2 --retry-all-errors --http1.1 \
		-fsSL https://mise.run | sh
fi

# Bats tests + cargo runs need to trust the project's mise.toml without
# the interactive prompt mise emits on first run.
mise trust --all >/dev/null 2>&1 || true
