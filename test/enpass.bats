#!/usr/bin/env bats
#
# test/fixtures/enpass is a throwaway vault created in Enpass (master password "password").
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	export ENPASS_VAULT="$TEST_TEMP_DIR/vault"
	mkdir -p "$ENPASS_VAULT"
	cp "$BATS_TEST_DIRNAME/fixtures/enpass/vault.json" "$BATS_TEST_DIRNAME/fixtures/enpass/vault.enpassdb" "$ENPASS_VAULT/"

	unset FNOX_ENPASS_PASSWORD
	export ENPASS_PASSWORD="password"
}

teardown() {
	_common_teardown
}

create_enpass_config() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.enpass]
type = "enpass"
vault = "$ENPASS_VAULT"

[secrets]
LOGIN_PASSWORD = { provider = "enpass", value = "password" }
SENSITIVE = { provider = "enpass", value = "sensitive text/sensitive field" }
EOF
}

@test "fnox get decrypts an item's password field" {
	create_enpass_config

	run "$FNOX_BIN" get LOGIN_PASSWORD
	assert_success
	assert_output "password"
}

@test "fnox get reads a sensitive text field by label" {
	create_enpass_config

	run "$FNOX_BIN" get SENSITIVE
	assert_success
	assert_output "sensitive"
}

@test "fnox exec resolves several Enpass secrets" {
	create_enpass_config

	run bash -c "'$FNOX_BIN' exec -- sh -c 'echo \"\$LOGIN_PASSWORD:\$SENSITIVE\"' 2>/dev/null"
	assert_success
	assert_output "password:sensitive"
}

@test "enpass provider resolves a relative vault from the declaring config" {
	mkdir -p project/services/worker
	mv "$ENPASS_VAULT" project/vault

	cat >project/fnox.toml <<EOF
[providers.enpass]
type = "enpass"
vault = "./vault"
EOF

	cat >project/services/worker/fnox.toml <<EOF
[secrets]
API_KEY = { provider = "enpass", value = "password" }
EOF

	cd project/services/worker
	run "$FNOX_BIN" get API_KEY
	assert_success
	assert_output "password"
}

@test "enpass provider respects FNOX_ENPASS_PASSWORD" {
	create_enpass_config
	unset ENPASS_PASSWORD
	export FNOX_ENPASS_PASSWORD="password"

	run "$FNOX_BIN" get LOGIN_PASSWORD
	assert_success
	assert_output "password"
}

@test "enpass provider reports a wrong or missing master password as an auth failure" {
	create_enpass_config

	ENPASS_PASSWORD=wrong run "$FNOX_BIN" get LOGIN_PASSWORD
	assert_failure
	assert_output --partial "auth_failed"
	assert_output --partial "Could not unlock the vault"

	unset ENPASS_PASSWORD
	run "$FNOX_BIN" --non-interactive get LOGIN_PASSWORD
	assert_failure
	assert_output --partial "auth_failed"
	assert_output --partial "Master password not set"
}

@test "enpass provider reports a missing item" {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.enpass]
type = "enpass"
vault = "$ENPASS_VAULT"

[secrets]
MISSING = { provider = "enpass", value = "no such item", if_missing = "error" }
EOF

	run "$FNOX_BIN" get MISSING
	assert_failure
	assert_output --partial "No item with that title"
}

@test "fnox provider test unlocks the Enpass vault" {
	create_enpass_config

	run "$FNOX_BIN" provider test enpass
	assert_success
	assert_output --partial "connection successful"
}
