#!/usr/bin/env bash
# Install mise into ~/.local/bin if it isn't already on PATH, then make
# sure ~/.local/bin is on PATH for the rest of the step. Source this from
# the pipeline (`source .buildkite/scripts/install-mise.sh`) so PATH
# changes survive into the next command.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

if ! command -v mise >/dev/null 2>&1; then
	curl -fsSL https://mise.run | sh
fi

# Bats tests + cargo runs need to trust the project's mise.toml without
# the interactive prompt mise emits on first run.
mise trust --all >/dev/null 2>&1 || true
