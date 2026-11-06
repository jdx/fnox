#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export FNOX_DAEMON=off FNOX_PROMPT_AUTH=false
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR"
}

teardown() {
	_common_teardown
}

@test "hook-env reports the schema error, not a missing local config file" {
	cat >fnox.toml <<'CONFIG'
root = true
[secrets]
VALID = { default = "1" }
TEST = { default = 1 }
CONFIG

	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output --partial "expected a string"
	refute_output --partial "Failed to read configuration file"
}

@test "hook-env reports a schema error in .config/fnox.local.toml" {
	cat >fnox.toml <<'CONFIG'
root = true
[secrets]
VALID = { default = "1" }
CONFIG
	mkdir -p .config
	cat >.config/fnox.local.toml <<'CONFIG'
[secrets]
TEST = { default = 1 }
CONFIG

	run "$FNOX_BIN" hook-env -s bash
	assert_success
	assert_output --partial "expected a string"
	refute_output --partial "Failed to read configuration file"
}
