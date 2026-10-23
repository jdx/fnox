#!/usr/bin/env bats
#
# Tests for `fnox exec --only` / `--except`: secrets outside the filter are
# neither resolved nor required.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR"

	# BROKEN's age key file does not exist and if_missing = "error", so
	# resolving it fails the run.
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets]
GOOD = { provider = "plain", value = "good-value" }
GOOD_TWO = { provider = "plain", value = "good-two" }
FILE_GOOD = { provider = "plain", value = "file-value", as_file = true }
BROKEN = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0=", if_missing = "error" }
TOML
	export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
}

teardown() {
	"$FNOX_BIN" daemon stop >/dev/null 2>&1 || true
	_common_teardown
}

@test "exec without a filter fails on the broken secret" {
	run "$FNOX_BIN" exec -- true
	assert_failure
}

@test "exec --only skips a broken secret outside the filter" {
	run "$FNOX_BIN" exec --only GOOD -- sh -c 'echo "good=$GOOD two=${GOOD_TWO-unset} broken=${BROKEN-unset}"'
	assert_success
	assert_output --partial "good=good-value two=unset broken=unset"
}

@test "exec --only accepts globs, repeats, and comma lists" {
	run "$FNOX_BIN" exec --only 'GOOD*' -- sh -c 'echo "$GOOD $GOOD_TWO ${BROKEN-unset}"'
	assert_success
	assert_output --partial "good-value good-two unset"

	run "$FNOX_BIN" exec --only GOOD --only GOOD_TWO -- sh -c 'echo "$GOOD $GOOD_TWO"'
	assert_success
	assert_output --partial "good-value good-two"

	run "$FNOX_BIN" exec --only GOOD,GOOD_TWO -- sh -c 'echo "$GOOD $GOOD_TWO"'
	assert_success
	assert_output --partial "good-value good-two"
}

@test "exec --except skips a broken secret" {
	run "$FNOX_BIN" exec --except BROKEN -- sh -c 'echo "$GOOD $GOOD_TWO"'
	assert_success
	assert_output --partial "good-value good-two"
}

@test "exec --only still applies if_missing to selected secrets" {
	run "$FNOX_BIN" exec --only BROKEN -- true
	assert_failure
}

@test "exec --only with an unknown name lists close matches" {
	run "$FNOX_BIN" exec --only GOOD_TW -- true
	assert_failure
	assert_output --partial "GOOD_TW"
	assert_output --partial "GOOD_TWO"
}

@test "exec --except with an unknown name is an error" {
	run "$FNOX_BIN" exec --except NOPE_NOPE_NOPE -- true
	assert_failure
	assert_output --partial "NOPE_NOPE_NOPE"
}

@test "exec --only with a glob that matches nothing is an error" {
	run "$FNOX_BIN" exec --only 'ZZZ*' -- true
	assert_failure
	assert_output --partial "ZZZ*"
}

@test "exec --only writes selected as_file secrets and omits the rest" {
	run "$FNOX_BIN" exec --only FILE_GOOD -- sh -c 'cat "$FILE_GOOD"; echo "good=${GOOD-unset}"'
	assert_success
	assert_output --partial "file-value"
	assert_output --partial "good=unset"
}

@test "exec --only leaves an inherited variable of an excluded secret alone" {
	GOOD_TWO=from-parent run "$FNOX_BIN" exec --only GOOD -- sh -c 'echo "$GOOD_TWO"'
	assert_success
	assert_output --partial "from-parent"
}

@test "filtered exec through the daemon does not poison later unfiltered calls" {
	cat >fnox.toml <<'TOML'
root = true

[daemon]
enabled = true

[providers.plain]
type = "plain"

[secrets]
GOOD = { provider = "plain", value = "good-value" }
GOOD_TWO = { provider = "plain", value = "good-two" }
FILE_GOOD = { provider = "plain", value = "file-value", as_file = true }
TOML

	run "$FNOX_BIN" exec --only GOOD -- sh -c 'echo "$GOOD ${GOOD_TWO-unset}"'
	assert_success
	assert_output --partial "good-value unset"

	run "$FNOX_BIN" exec -- sh -c 'echo "$GOOD $GOOD_TWO"; cat "$FILE_GOOD"'
	assert_success
	assert_output --partial "good-value good-two"
	assert_output --partial "file-value"

	run "$FNOX_BIN" exec --only GOOD_TWO -- sh -c 'echo "${GOOD-unset} $GOOD_TWO"'
	assert_success
	assert_output --partial "unset good-two"
}
