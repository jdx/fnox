#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
	export NO_COLOR=1
	if ! command -v curl >/dev/null 2>&1; then
		skip "curl not installed"
	fi
	# Each create logs a line and mints a numbered token; revoke logs the ID
	cat >"$TEST_TEMP_DIR/create.sh" <<SCRIPT
#!/usr/bin/env bash
echo created >>"$TEST_TEMP_DIR/created.log"
n=\$(wc -l <"$TEST_TEMP_DIR/created.log" | tr -d ' ')
printf '{"credentials":{"API_TOKEN":"leased-token-%s"},"expires_at":"2099-01-01T00:00:00Z","lease_id":"proxy-lease-%s"}\n' "\$n" "\$n"
SCRIPT
	cat >"$TEST_TEMP_DIR/revoke.sh" <<SCRIPT
#!/usr/bin/env bash
echo "\$FNOX_LEASE_ID" >>"$TEST_TEMP_DIR/revoked.log"
SCRIPT
	chmod +x "$TEST_TEMP_DIR/create.sh" "$TEST_TEMP_DIR/revoke.sh"
	# The rule targets loopback so no request leaves the machine: the proxy
	# injects the lease and tries the upstream, where nothing listens.
	cat >fnox.toml <<EOF
root = true

[leases.api]
type = "command"
create_command = "$TEST_TEMP_DIR/create.sh"
revoke_command = "$TEST_TEMP_DIR/revoke.sh"

[proxy]
allow_private = ["127.0.0.1"]

[[proxy.rules]]
lease = "api"
credential = "API_TOKEN"
domain = "127.0.0.1"
EOF
}

teardown() {
	_common_teardown
}

@test "proxy rules shows a lease rule" {
	run "$FNOX_BIN" proxy rules
	assert_success
	assert_output --partial "lease:api -> https://127.0.0.1"
	assert_output --partial "env=API_TOKEN"
}

@test "proxy run creates a lease on first use, reuses it, and revokes it at exit" {
	run "$FNOX_BIN" proxy run -- sh -c '
		test ! -e "'"$TEST_TEMP_DIR"'/created.log" && echo "not created yet"
		echo "child sees $API_TOKEN"
		request() {
			curl --noproxy "" -sS -o /dev/null -w "%{http_code}\n" \
				-H "authorization: Bearer $API_TOKEN" https://127.0.0.1/
		}
		echo "first $(request)"
		echo "second $(request)"
	'
	assert_success
	assert_line "not created yet"
	assert_output --regexp 'child sees fnox_proxy_[0-9a-f]+'
	assert_output --partial 'injected=["lease:api"]'
	assert_line "first 502"
	assert_line "second 502"
	refute_output --partial leased-token
	run cat "$TEST_TEMP_DIR/created.log"
	assert_output "created"
	run cat "$TEST_TEMP_DIR/revoked.log"
	assert_output "proxy-lease-1"
	run "$FNOX_BIN" lease list --json
	assert_output --partial '"label": "fnox-proxy-api"'
	assert_output --partial '"status": "revoked"'
}

@test "proxy run doesn't create a lease nothing uses" {
	run "$FNOX_BIN" proxy run -- true
	assert_success
	assert_file_not_exists "$TEST_TEMP_DIR/created.log"
	assert_file_not_exists "$TEST_TEMP_DIR/revoked.log"
}

@test "proxy run rejects a rule for a lease that isn't configured" {
	sed -i.bak 's/^lease = "api"/lease = "missing"/' fnox.toml
	run "$FNOX_BIN" proxy run -- true
	assert_failure
	assert_output --partial "unknown lease 'missing'"
}

@test "proxy run rejects a rule that sets both secret and lease" {
	echo 'secret = "API_TOKEN"' >>fnox.toml
	run "$FNOX_BIN" proxy run -- true
	assert_failure
	assert_output --partial "sets both secret"
}
