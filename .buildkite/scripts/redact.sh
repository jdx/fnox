#!/usr/bin/env bash
# Register fnox-managed secrets with the Buildkite agent's redaction list so
# they don't leak into job logs, then sanity-check round-tripping a secret.
# Skips silently when no age key is available (forks/external runs).
set -euo pipefail

if [[ ! -f "$HOME/.config/fnox/age.txt" ]]; then
	echo "No fnox age key present; skipping ci-redact"
	exit 0
fi

fnox ci-redact
# shellcheck disable=SC2016
fnox run -- sh -c 'echo MY_UNIMPORTANT_SECRET: $MY_UNIMPORTANT_SECRET'
