#!/usr/bin/env bash
# Decide which bats tags to filter for this build.
#
# Mirrors the prior GitHub Actions logic: expensive integration tests are
# skipped by default, but run in full on release-plz PRs so they gate the
# release before the bot's PR merges.
set -euo pipefail

if [[ ${BUILDKITE_PULL_REQUEST:-false} != "false" && ${BUILDKITE_BRANCH:-} == release-plz* ]]; then
	tags=""
else
	tags="!expensive"
fi

export BATS_FILTER_TAGS="$tags"
printf 'export BATS_FILTER_TAGS=%q\n' "$tags" >>"$BUILDKITE_ENV_FILE"
echo "BATS_FILTER_TAGS=$tags"
