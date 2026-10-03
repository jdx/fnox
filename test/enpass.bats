#!/usr/bin/env bats
#
# Reads the synthetic vault in test/fixtures/enpass (see write_bats_fixture in enpass.rs).
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	export ENPASS_VAULT="$TEST_TEMP_DIR/vault"
	mkdir -p "$ENPASS_VAULT"
	cp "$BATS_TEST_DIRNAME/fixtures/enpass/vault.json" "$BATS_TEST_DIRNAME/fixtures/enpass/vault.enpassdb" "$ENPASS_VAULT/"

	unset FNOX_ENPASS_PASSWORD
	export ENPASS_PASSWORD="correct horse battery staple"
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
GH_PASSWORD = { provider = "enpass", value = "GitHub" }
GH_USER = { provider = "enpass", value = "GitHub/username" }
GH_TOKEN = { provider = "enpass", value = "GitHub/API Token" }
DB_PASSWORD = { provider = "enpass", value = "Prod/DB" }
EOF
}

@test "fnox get reads an item's password by default" {
	create_enpass_config

	run "$FNOX_BIN" get GH_PASSWORD
	assert_success
	assert_output "hunter2"
}

@test "fnox get reads a named field and a title containing a slash" {
	create_enpass_config

	run "$FNOX_BIN" get GH_USER
	assert_success
	assert_output "octocat"

	run "$FNOX_BIN" get GH_TOKEN
	assert_success
	assert_output "ghp_example"

	run "$FNOX_BIN" get DB_PASSWORD
	assert_success
	assert_output "slash-title"
}

@test "fnox exec resolves several Enpass secrets" {
	create_enpass_config

	run bash -c "'$FNOX_BIN' exec -- sh -c 'echo \"\$GH_USER:\$GH_PASSWORD:\$DB_PASSWORD\"' 2>/dev/null"
	assert_success
	assert_output "octocat:hunter2:slash-title"
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
API_KEY = { provider = "enpass", value = "GitHub/API Token" }
EOF

	cd project/services/worker
	run "$FNOX_BIN" get API_KEY
	assert_success
	assert_output "ghp_example"
}

@test "enpass provider respects FNOX_ENPASS_PASSWORD" {
	create_enpass_config
	unset ENPASS_PASSWORD
	export FNOX_ENPASS_PASSWORD="correct horse battery staple"

	run "$FNOX_BIN" get GH_PASSWORD
	assert_success
	assert_output "hunter2"
}

@test "enpass provider reports a wrong or missing master password as an auth failure" {
	create_enpass_config

	ENPASS_PASSWORD=wrong run "$FNOX_BIN" get GH_PASSWORD
	assert_failure
	assert_output --partial "auth_failed"
	assert_output --partial "Could not unlock the vault"

	unset ENPASS_PASSWORD
	run "$FNOX_BIN" --non-interactive get GH_PASSWORD
	assert_failure
	assert_output --partial "auth_failed"
	assert_output --partial "Master password not set"
}

@test "enpass provider skips trashed items and rejects ambiguous titles" {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.enpass]
type = "enpass"
vault = "$ENPASS_VAULT"

[secrets]
TRASHED = { provider = "enpass", value = "Binned", if_missing = "error" }
TWIN = { provider = "enpass", value = "Twin", if_missing = "error" }
EOF

	run "$FNOX_BIN" get TRASHED
	assert_failure
	assert_output --partial "No item with that title"

	run "$FNOX_BIN" get TWIN
	assert_failure
	assert_output --partial "More than one item"
}

@test "fnox provider test unlocks the Enpass vault" {
	create_enpass_config

	run "$FNOX_BIN" provider test enpass
	assert_success
	assert_output --partial "connection successful"
}
