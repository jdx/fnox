#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "plain provider stores values as-is" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret with plain provider
	run "$FNOX_BIN" set MY_SECRET "test-value" --provider plain
	assert_success

	# Verify the secret was stored in plain text
	assert_config_contains "MY_SECRET"
	assert_config_contains "test-value"

	# Should be able to get it back
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "test-value"
}

@test "plain provider as default provider" {
	# Create config with plain as default provider
	cat >fnox.toml <<'EOF'
root = true
default_provider = "plain"

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret without specifying provider - should use default
	run "$FNOX_BIN" set MY_SECRET "secret-value"
	assert_success

	# Verify the secret was stored in plain text
	assert_config_contains "MY_SECRET"
	assert_config_contains "secret-value"

	# Get should work
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "secret-value"
}

@test "plain provider auto-selected when only provider" {
	# Create config with plain as the only provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret without specifying provider - should auto-select plain
	run "$FNOX_BIN" set AUTO_SECRET "auto-value"
	assert_success

	# Verify the secret was stored
	assert_config_contains "AUTO_SECRET"
	assert_config_contains "auto-value"

	# Get should work
	run "$FNOX_BIN" get AUTO_SECRET
	assert_success
	assert_output "auto-value"
}

@test "plain provider with special characters" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret with special characters
	run "$FNOX_BIN" set SPECIAL_SECRET "value with spaces & symbols!@#$%^&*()"
	assert_success

	# Get should return the exact value
	run "$FNOX_BIN" get SPECIAL_SECRET
	assert_success
	assert_output "value with spaces & symbols!@#$%^&*()"
}

@test "plain provider with multiline values" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret with newlines (escaped)
	run "$FNOX_BIN" set MULTILINE_SECRET "line1\nline2\nline3"
	assert_success

	# Get should preserve the content
	run "$FNOX_BIN" get MULTILINE_SECRET
	assert_success
	# Note: The actual output will depend on how fnox handles multiline values
	assert_output --partial "line1"
}

@test "plain provider with empty value" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret with empty value
	run "$FNOX_BIN" set EMPTY_SECRET ""
	assert_success

	# Get should return empty string
	run "$FNOX_BIN" get EMPTY_SECRET
	assert_success
	assert_output ""
}

@test "plain provider with profile" {
	# Create config with plain provider in a profile
	cat >fnox.toml <<'EOF'
root = true

[secrets]

[profiles.dev]

[profiles.dev.providers.plain]
type = "plain"

[profiles.dev.secrets]
EOF

	# Set a secret in dev profile
	run "$FNOX_BIN" set --profile dev DEV_SECRET "dev-value"
	assert_success

	# Get from dev profile should work
	run "$FNOX_BIN" get --profile dev DEV_SECRET
	assert_success
	assert_output "dev-value"

	# Secret should be in plain text in config
	assert_config_contains "dev-value"
}

@test "plain provider test connection" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Test provider connection
	run "$FNOX_BIN" provider test plain
	assert_success
	assert_output --partial "plain"
}

@test "plain provider in doctor output" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Run doctor command
	run "$FNOX_BIN" doctor
	assert_success
	assert_output --partial "plain (plain)"
}

@test "plain provider updates existing secret" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set initial value
	run "$FNOX_BIN" set UPDATE_SECRET "initial-value"
	assert_success

	# Verify initial value
	run "$FNOX_BIN" get UPDATE_SECRET
	assert_success
	assert_output "initial-value"

	# Update the value
	run "$FNOX_BIN" set UPDATE_SECRET "updated-value"
	assert_success

	# Verify updated value
	run "$FNOX_BIN" get UPDATE_SECRET
	assert_success
	assert_output "updated-value"

	# Old value should not be in config
	assert_config_not_contains "initial-value"
	assert_config_contains "updated-value"
}

@test "plain provider with description" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret with description
	run "$FNOX_BIN" set DESCRIBED_SECRET "value" --description "This is a test secret"
	assert_success

	# Verify description is in config
	assert_config_contains "This is a test secret"
}

@test "plain provider list shows secrets" {
	# Create config with plain provider and some secrets
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
SECRET1 = { provider = "plain", value = "value1", description = "First secret" }
SECRET2 = { provider = "plain", value = "value2", description = "Second secret" }
SECRET3 = { provider = "plain", value = "value3" }
EOF

	# List should show all secrets
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "SECRET1"
	assert_output --partial "SECRET2"
	assert_output --partial "SECRET3"
	assert_output --partial "First secret"
	assert_output --partial "Second secret"
}
