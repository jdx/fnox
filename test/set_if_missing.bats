#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
}

@test "fnox set --if-missing error does not panic" {
	run "$FNOX_BIN" set MY_VAR --if-missing error
	assert_success
}

@test "fnox set --if-missing warn does not panic" {
	run "$FNOX_BIN" set MY_VAR --if-missing warn
	assert_success
}

@test "fnox set --if-missing ignore does not panic" {
	run "$FNOX_BIN" set MY_VAR --if-missing ignore
	assert_success
}

@test "fnox set --if-missing rejects invalid value" {
	run "$FNOX_BIN" set MY_VAR --if-missing invalid
	assert_failure
	assert_output --partial "possible values: error, warn, ignore"
}

@test "fnox set --if-missing error writes if_missing to config" {
	run "$FNOX_BIN" set MY_VAR --if-missing error
	assert_success
	assert [ -f fnox.toml ]
	run grep "if_missing" fnox.toml
	assert_success
	assert_output --partial 'if_missing = "error"'
}

@test "fnox set --if-missing combined with --description does not panic" {
	run "$FNOX_BIN" set MY_VAR --description "test secret" --if-missing warn
	assert_success
}
