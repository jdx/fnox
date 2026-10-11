#!/usr/bin/env bats
#
# A provider's env_dependencies() (credentials it reads from the environment)
# can be fnox secrets resolved by another provider. These tests use a fake
# `vault` CLI that prints the VAULT_TOKEN it was given, so they run offline.

setup() {
	load 'test_helper/common_setup'
	_common_setup

	mkdir -p "$TEST_TEMP_DIR/bin"
	cat >"$TEST_TEMP_DIR/bin/vault" <<'SCRIPT'
#!/usr/bin/env bash
printf 'token=%s\n' "$VAULT_TOKEN"
SCRIPT
	chmod +x "$TEST_TEMP_DIR/bin/vault"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"
	unset VAULT_TOKEN FNOX_VAULT_TOKEN VAULT_ADDR FNOX_VAULT_ADDR FNOX_DAEMON

	cat >"$FNOX_CONFIG_FILE" <<'TOML'
root = true

[providers]
plain = { type = "plain" }
vault = { type = "vault", address = "http://127.0.0.1:1", path = "secret" }

[secrets]
VAULT_TOKEN = { provider = "plain", value = "token-from-fnox" }
APP_SECRET = { provider = "vault", value = "app/value" }
TOML
}

teardown() {
	_common_teardown
}

@test "fnox get resolves provider credentials stored as fnox secrets" {
	run "$FNOX_BIN" get APP_SECRET
	assert_success
	assert_output "token=token-from-fnox"
}

@test "fnox get keeps provider credentials already set in the environment" {
	VAULT_TOKEN=token-from-env run "$FNOX_BIN" get APP_SECRET
	assert_success
	assert_output "token=token-from-env"
}

@test "fnox exec resolves provider credentials stored as fnox secrets" {
	run "$FNOX_BIN" exec -- sh -c 'printf "%s\n" "$APP_SECRET"'
	assert_success
	assert_output "token=token-from-fnox"
}
