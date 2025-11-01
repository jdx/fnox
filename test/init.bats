#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox init creates default config file" {
	assert_fnox_success init
	assert_file_exists "fnox.toml"
}

@test "fnox init fails if config already exists" {
	# First init should succeed
	assert_fnox_success init

	# Second init should fail
	assert_fnox_failure init
	assert_output --partial "already exists"
}

@test "fnox init creates config with specified path" {
	assert_fnox_success --config custom-fnox.toml init
	assert_file_exists "custom-fnox.toml"
}

@test "fnox init creates minimal config" {
	assert_fnox_success init
	assert_file_exists "fnox.toml"
}

@test "fnox commands show helpful error when no config found" {
	# Create an isolated directory in /tmp with no parent configs
	local isolated_dir
	isolated_dir=$(mktemp -d /tmp/fnox-no-config-test.XXXXXX)

	# Change to isolated directory
	cd "$isolated_dir" || exit 1

	# Try to run a command that needs config
	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "fnox init"
	assert_output --partial "No configuration file found"

	# Clean up
	rm -rf "$isolated_dir"
}
