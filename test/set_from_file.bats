#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "set --from-file preserves a trailing newline for as_file secrets" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
SSH_PRIVATE_KEY = { provider = "plain", value = "placeholder", as_file = true }
EOF

	cat >ssh_key <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
test-key-data
-----END OPENSSH PRIVATE KEY-----
EOF

	run "$FNOX_BIN" set SSH_PRIVATE_KEY --from-file ssh_key
	assert_success

	run "$FNOX_BIN" exec sh -c 'cmp -s "$SSH_PRIVATE_KEY" ssh_key'
	assert_success
}

@test "set --from-file reports a missing input file" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	run "$FNOX_BIN" set MY_SECRET --from-file does-not-exist --provider plain
	assert_failure
	assert_output --partial "Failed to read secret file: does-not-exist"
}
