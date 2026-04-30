#!/usr/bin/env bash
# Set up the age key for fnox so encrypted secrets in fnox.toml can be decrypted.
#
# Skips silently when AGE_SECRET is unavailable (e.g. fork PRs in a
# trust-based pipeline) so jobs can fall back to the if_missing="warn"
# behavior configured in fnox.toml.
set -euo pipefail

if [[ -z ${AGE_SECRET:-} ]]; then
	echo "AGE_SECRET not set; skipping age key setup"
	exit 0
fi

mkdir -p ~/.config/fnox
printf '%s\n' "$AGE_SECRET" >~/.config/fnox/age.txt
chmod 600 ~/.config/fnox/age.txt
