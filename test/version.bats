#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox --version prints version" {
	run "$FNOX_BIN" --version
	assert_success
	assert_fnox_version_output
}

@test "fnox --help prints help" {
	run "$FNOX_BIN" --help
	assert_success
	assert_output --partial "Usage:"
	assert_output --partial "fnox"
}

@test "fnox version prints version" {
	run "$FNOX_BIN" version
	assert_success
	assert_fnox_version_output
}

@test "fnox shows error with unknown flag" {
	run "$FNOX_BIN" --unknown-flag
	assert_failure
	assert_output --partial "unexpected argument"
}
