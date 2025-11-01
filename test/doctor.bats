#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox doctor shows config info" {
	create_test_config
	assert_fnox_success doctor
	assert_output --partial "Fnox Doctor Report"
	assert_output --partial "Configuration:"
	assert_output --partial "File:"
	assert_output --partial "Profile:"
}

@test "fnox doctor shows secrets info" {
	create_test_config
	assert_fnox_success doctor
	assert_output --partial "Secrets:"
	assert_output --partial "Count:"
}

@test "fnox doctor shows providers info" {
	create_test_config
	assert_fnox_success doctor
	assert_output --partial "Providers:"
	assert_output --partial "age"
}

@test "fnox doctor shows environment info" {
	create_test_config
	assert_fnox_success doctor
	assert_output --partial "Environment:"
	assert_output --partial "FNOX_PROFILE"
}

@test "fnox doctor shows summary" {
	create_test_config
	assert_fnox_success doctor
	assert_output --partial "Summary:"
	assert_output --partial "Total secrets:"
	assert_output --partial "Total providers:"
}

@test "fnox doctor shows tips" {
	create_test_config
	assert_fnox_success doctor
	assert_output --partial "Tips:"
}

@test "fnox doctor with profile" {
	create_test_config
	assert_fnox_success doctor --profile test
	assert_output --partial "Profile: test"
}

@test "fnox doctor with no config" {
	# Use explicit path to non-existent config to bypass recursive loading
	run "$FNOX_BIN" --config /tmp/nonexistent-fnox-config.toml doctor
	assert_failure
	assert_output --partial "Failed to read"
}

@test "fnox doctor with empty config" {
	echo "root = true" >"${FNOX_CONFIG_FILE:-fnox.toml}"
	assert_fnox_success doctor
	assert_output --partial "Count: 0"
	assert_output --partial "Add secrets"
}

@test "fnox doctor shows provider health" {
	create_test_config
	# This might show connection errors for real providers, but that's expected
	assert_fnox_success doctor
	assert_output --partial "Provider Health"
}

@test "fnox doctor with many secrets" {
	create_test_config

	# Add multiple secrets
	for i in {1..15}; do
		cat >>"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF

[secrets.secret_$i]
value = "value_$i"
EOF
	done

	assert_fnox_success doctor
	assert_output --partial "Count: 16" # 1 from create_test_config + 15 new ones
}
