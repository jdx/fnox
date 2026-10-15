#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox set reads piped stdin when --description is given" {
	cat >fnox.toml <<EOF
root = true
[providers.plain]
type = "plain"
[secrets]
EOF

	run bash -c "echo piped-value | '$FNOX_BIN' set A -p plain -d 'desc'"
	assert_success

	run "$FNOX_BIN" get A
	assert_success
	assert_output "piped-value"
	run grep 'description = "desc"' fnox.toml
	assert_success
}

@test "fnox set -d with empty stdin sets only metadata" {
	cat >fnox.toml <<EOF
root = true
[providers.plain]
type = "plain"
[secrets]
EOF

	run bash -c "'$FNOX_BIN' set A -d 'desc' </dev/null"
	assert_success
	run grep 'description = "desc"' fnox.toml
	assert_success
}
