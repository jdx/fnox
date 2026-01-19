#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# Helper to create config with plain provider
setup_plain_provider() {
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
TEST_SECRET = { provider = "plain", value = "test" }
EOF
}

# Helper to create config with multiple providers
setup_multiple_providers() {
	cat >fnox.toml <<EOF
root = true

[providers.plain1]
type = "plain"

[providers.plain2]
type = "plain"

[secrets]
TEST_SECRET = { provider = "plain1", value = "test" }
EOF
}

@test "fnox provider test requires provider name or --all" {
	setup_plain_provider

	assert_fnox_failure provider test
	assert_output --partial "specify a provider name or use --all"
}

@test "fnox provider test single provider succeeds" {
	setup_plain_provider

	assert_fnox_success provider test plain
	assert_output --partial "plain"
	assert_output --partial "connection successful"
}

@test "fnox provider test --all tests all providers" {
	setup_multiple_providers

	assert_fnox_success provider test --all
	assert_output --partial "Testing 2 providers"
	assert_output --partial "plain1"
	assert_output --partial "plain2"
	assert_output --partial "All 2 providers passed"
}

@test "fnox provider test -a is alias for --all" {
	setup_multiple_providers

	assert_fnox_success provider test -a
	assert_output --partial "Testing 2 providers"
	assert_output --partial "All 2 providers passed"
}

@test "fnox provider test --all with no providers" {
	cat >fnox.toml <<EOF
root = true

[secrets]
EOF

	assert_fnox_success provider test --all
	assert_output --partial "No providers configured"
}

@test "fnox provider test --all shows count in summary" {
	setup_plain_provider

	assert_fnox_success provider test --all
	assert_output --partial "Testing 1 provider..."
	assert_output --partial "All 1 provider passed"
}

@test "fnox provider test nonexistent provider fails" {
	setup_plain_provider

	assert_fnox_failure provider test nonexistent
	assert_output --partial "not found"
}

@test "fnox provider test visible alias t works" {
	setup_plain_provider

	assert_fnox_success provider t plain
	assert_output --partial "connection successful"
}
