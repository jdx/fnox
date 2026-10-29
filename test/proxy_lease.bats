#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
	export NO_COLOR=1
	if ! command -v curl >/dev/null 2>&1; then
		skip "curl not installed"
	fi
	# The lease records the length of the parent credential it was given and
	# its label; revoking logs the lease ID.
	cat >mint.sh <<SCRIPT
#!/bin/sh
echo "\${#PARENT_TOKEN} \$FNOX_LEASE_LABEL" >>"$TEST_TEMP_DIR/minted.log"
printf '{"credentials":{"FORGE_TOKEN":"minted-token-value"},"lease_id":"proxy-lease-1","expires_at":"2099-01-01T00:00:00Z"}'
SCRIPT
	cat >revoke.sh <<SCRIPT
#!/bin/sh
echo "\$FNOX_LEASE_ID" >>"$TEST_TEMP_DIR/revoked.log"
SCRIPT
	chmod +x mint.sh revoke.sh
	# The rule targets loopback so no request leaves the machine: the proxy
	# injects the lease and tries the upstream, where nothing listens.
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
PARENT_TOKEN = { provider = "plain", value = "parent-secret-value", env = false }

[leases.forge]
type = "command"
create_command = "$TEST_TEMP_DIR/mint.sh"
revoke_command = "$TEST_TEMP_DIR/revoke.sh"

[proxy]
allow_private = ["127.0.0.1"]

[[proxy.rules]]
lease = "forge"
credential = "FORGE_TOKEN"
domain = "127.0.0.1"
header = "private-token"
methods = ["POST"]
EOF
}

teardown() {
	_common_teardown
}

@test "proxy rules show a lease rule" {
	run "$FNOX_BIN" proxy rules
	assert_success
	assert_output --partial "lease:forge -> https://127.0.0.1 methods=POST paths=* header=private-token env=FORGE_TOKEN credential=FORGE_TOKEN"
}

@test "proxy run mints a lease on first use, injects it, and revokes it at exit" {
	run "$FNOX_BIN" proxy run -- sh -c '
		test "$FORGE_TOKEN" != "${FORGE_TOKEN#fnox_proxy_}" && echo "placeholder ok"
		test -z "$PARENT_TOKEN" && echo "no parent"
		test ! -e minted.log && echo "nothing minted yet"
		request() {
			curl --noproxy "" -sS -o /dev/null -w "%{http_code}\n" \
				--data "" -H "private-token: $FORGE_TOKEN" https://127.0.0.1/notes
		}
		echo "first $(request)"
		echo "second $(request)"
	'
	assert_success
	assert_line "placeholder ok"
	assert_line "no parent"
	assert_line "nothing minted yet"
	assert_line "first 502"
	assert_line "second 502"
	assert_output --partial 'injected=["lease:forge"]'
	# Minted once for both requests, with the parent credential in reach
	assert_equal "$(cat minted.log)" "19 fnox-proxy-forge"
	refute_output --partial "minted-token-value"
	refute_output --partial "parent-secret-value"
	assert_equal "$(cat revoked.log)" "proxy-lease-1"

	run "$FNOX_BIN" lease list
	assert_success
	assert_output --partial "forge"
	assert_output --partial "revoked"
}

@test "proxy run does not mint a lease that no request needs" {
	run "$FNOX_BIN" proxy run -- true
	assert_success
	assert_file_not_exists minted.log
	assert_file_not_exists revoked.log
}

@test "proxy run rejects a rule for a lease that isn't declared" {
	sed -i.bak 's/^lease = "forge"/lease = "missing"/' fnox.toml
	run "$FNOX_BIN" proxy run -- true
	assert_failure
	assert_output --partial "unknown lease 'missing'"
}
