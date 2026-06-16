#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup --git
}

teardown() {
	_common_teardown
}

@test "fnox scan passes when no secrets are found" {
	echo 'name = "fnox"' >safe.toml

	assert_fnox_success scan
	assert_output --partial "No potential secrets found"
}

@test "fnox scan fails when known token is found" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env

	assert_fnox_failure scan
	assert_output --partial "github-token"
	assert_output --partial "secrets.env"
}

@test "fnox scan redacts secret values" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env

	assert_fnox_failure scan
	assert_output --partial "ghp_"
	refute_output --partial "abcdefghijklmnopqrstuvwxyz123456"
}

@test "fnox scan quiet prints only affected files" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env
	echo 'name = "fnox"' >safe.toml

	run bash -c '"$1" scan --quiet 2>/dev/null' _ "$FNOX_BIN"
	assert_failure
	assert_output "secrets.env"
}

@test "fnox scan quiet json prints affected files as json" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env
	echo 'name = "fnox"' >safe.toml

	run bash -c '"$1" scan --quiet --format json 2>/dev/null' _ "$FNOX_BIN"
	assert_failure
	echo "$output" | /usr/bin/python3 -m json.tool >/dev/null
	assert_output --partial '"secrets.env"'
	refute_output --partial '"findings"'
}

@test "fnox scan json emits parseable findings and summary" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env

	run bash -c '"$1" scan --format json 2>/dev/null' _ "$FNOX_BIN"
	assert_failure
	echo "$output" | /usr/bin/python3 -m json.tool >/dev/null
	assert_output --partial '"findings"'
	assert_output --partial '"summary"'
	assert_output --partial '"detector": "github-token"'
}

@test "fnox scan human output uses lowercase severity" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env

	assert_fnox_failure scan
	assert_output --partial "[github-token high]"
	refute_output --partial "[github-token High]"
}

@test "fnox scan accepts positional directory" {
	mkdir -p src
	echo 'password = "abc12345!"' >src/config.env

	assert_fnox_failure scan src
	assert_output --partial "src/config.env"
}

@test "fnox scan ignore suppresses matching files" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >ignored.env

	assert_fnox_success scan --ignore ignored.env
	assert_output --partial "No potential secrets found"
}

@test "fnox scan skips vcs build and vendor directories" {
	mkdir -p .git target node_modules vendor dist build
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >.git/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >target/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >node_modules/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >vendor/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >dist/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >build/secrets.env
	echo 'name = "fnox"' >safe.toml

	assert_fnox_success scan
	assert_output --partial "No potential secrets found"
}

@test "fnox scan includes hidden files" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >.env

	assert_fnox_failure scan
	assert_output --partial ".env"
}

@test "fnox scan does not skip files named like excluded directories" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >build

	assert_fnox_failure scan
	assert_output --partial "build"
}
