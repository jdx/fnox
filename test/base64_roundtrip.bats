#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox base64 encode / decode returns correct string" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret with plain provider
	run "$FNOX_BIN" set --base64-encode MY_SECRET "test-value" --provider plain
	assert_success

	# Verify the secret was stored in plain text
	assert_config_contains "MY_SECRET"
	assert_config_contains "dGVzdC12YWx1ZQ=="

	# Should be able to get encoded secret
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "dGVzdC12YWx1ZQ=="

	# Should be able to get decoded secret
	run "$FNOX_BIN" get --base64-decode MY_SECRET
	assert_success
	assert_output "test-value"
}

@test "fnox base64 decode returns errors" {
	# Create config with plain provider
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a secret with plain provider
	run "$FNOX_BIN" set MY_SECRET "!!!" --provider plain
	assert_success

	# Verify the secret was stored in plain text
	assert_config_contains "MY_SECRET"
	assert_config_contains "!!!"

	# Should fail when decoding non base64 secret
	run "$FNOX_BIN" get --base64-decode MY_SECRET
	assert_failure
	assert_output --partial "× Failed to decode secret: Failed to base64 decode secret"
}
