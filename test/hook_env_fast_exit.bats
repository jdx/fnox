#!/usr/bin/env bats

# An unchanged `fnox hook-env -s <shell>` can exit before the CLI starts up.
# Debug output takes the normal path, which reports why it exited.

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export FNOX_DAEMON=off
	cat >fnox.toml <<'CONFIG'
root = true
[secrets]
FOO = { default = "bar" }
CONFIG
}

teardown() {
	_common_teardown
}

@test "unchanged hook exits quietly and reloads after a config change" {
	eval "$("$FNOX_BIN" hook-env -s bash 2>/dev/null)"
	[ "$FOO" = bar ]

	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output ""

	sleep 1
	touch fnox.toml
	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output --partial "__FNOX_SESSION"
}

@test "unchanged hook in debug output mode reports its early exit" {
	# FNOX_* variables are part of the session, so set this before creating it.
	export FNOX_SHELL_OUTPUT=debug
	eval "$("$FNOX_BIN" hook-env -s bash 2>/dev/null)"

	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output --partial "fnox: early exit - no changes detected"
}

@test "unchanged hook with an unsupported shell still reports the error" {
	eval "$("$FNOX_BIN" hook-env -s bash 2>/dev/null)"

	run "$FNOX_BIN" hook-env -s tcsh
	assert_failure
}
