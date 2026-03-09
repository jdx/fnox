#!/usr/bin/env bats
#
# Command Lease Backend Tests
#
# These tests verify the generic command lease backend. No external services
# are required — the backend runs a shell command that outputs JSON credentials.

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# Helper: create a script that outputs valid JSON credentials
create_cred_script() {
	cat >"$TEST_TEMP_DIR/create-creds.sh" <<'SCRIPT'
#!/usr/bin/env bash
cat <<EOF
{
  "credentials": {
    "MY_TOKEN": "tok-abc123",
    "MY_SECRET": "sec-xyz789"
  },
  "expires_at": "2099-01-01T00:00:00Z",
  "lease_id": "cmd-test-lease-1"
}
EOF
SCRIPT
	chmod +x "$TEST_TEMP_DIR/create-creds.sh"
}

# Helper: create a script that uses FNOX_LEASE_DURATION and FNOX_LEASE_LABEL
create_cred_script_with_env() {
	cat >"$TEST_TEMP_DIR/create-creds-env.sh" <<'SCRIPT'
#!/usr/bin/env bash
cat <<EOF
{
  "credentials": {
    "DURATION_RECEIVED": "$FNOX_LEASE_DURATION",
    "LABEL_RECEIVED": "$FNOX_LEASE_LABEL"
  },
  "lease_id": "cmd-env-lease"
}
EOF
SCRIPT
	chmod +x "$TEST_TEMP_DIR/create-creds-env.sh"
}

# Helper: create a revoke script that logs the lease ID
create_revoke_script() {
	cat >"$TEST_TEMP_DIR/revoke-creds.sh" <<SCRIPT
#!/usr/bin/env bash
echo "\$FNOX_LEASE_ID" >> "$TEST_TEMP_DIR/revoked.log"
SCRIPT
	chmod +x "$TEST_TEMP_DIR/revoke-creds.sh"
}

# Helper: create a script that exits with failure
create_failing_script() {
	cat >"$TEST_TEMP_DIR/fail.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo "something went wrong" >&2
exit 1
SCRIPT
	chmod +x "$TEST_TEMP_DIR/fail.sh"
}

# Helper: create a script that outputs invalid JSON
create_bad_json_script() {
	cat >"$TEST_TEMP_DIR/bad-json.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo "not json at all"
SCRIPT
	chmod +x "$TEST_TEMP_DIR/bad-json.sh"
}

# Helper: create a script that outputs JSON without credentials
create_no_creds_script() {
	cat >"$TEST_TEMP_DIR/no-creds.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo '{"other": "data"}'
SCRIPT
	chmod +x "$TEST_TEMP_DIR/no-creds.sh"
}

# Helper: create fnox config with command lease backend
create_command_config() {
	local create_cmd="${1:-$TEST_TEMP_DIR/create-creds.sh}"
	local revoke_cmd="${2:-}"
	if [ -n "$revoke_cmd" ]; then
		cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_cmd]
type = "command"
create_command = "$create_cmd"
revoke_command = "$revoke_cmd"
EOF
	else
		cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_cmd]
type = "command"
create_command = "$create_cmd"
EOF
	fi
}

@test "command backend: lease create outputs credentials in json format" {
	create_cred_script
	create_command_config

	run "$FNOX_BIN" lease create test_cmd --duration 15m --format json
	assert_success
	assert_output --partial "MY_TOKEN"
	assert_output --partial "tok-abc123"
	assert_output --partial "MY_SECRET"
	assert_output --partial "sec-xyz789"
	assert_output --partial "cmd-test-lease-1"
}

@test "command backend: lease create outputs credentials in env format" {
	create_cred_script
	create_command_config

	run "$FNOX_BIN" lease create test_cmd --duration 15m --format env
	assert_success
	assert_output --partial "export MY_TOKEN="
	assert_output --partial "export MY_SECRET="
}

@test "command backend: lease create outputs credentials in shell format" {
	create_cred_script
	create_command_config

	run "$FNOX_BIN" lease create test_cmd --duration 15m --format shell
	assert_success
	assert_output --partial "created"
	assert_output --partial "MY_TOKEN"
}

@test "command backend: exec injects lease credentials into subprocess" {
	create_cred_script
	create_command_config

	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "MY_TOKEN=tok-abc123"
	assert_output --partial "MY_SECRET=sec-xyz789"
}

@test "command backend: passes FNOX_LEASE_DURATION and FNOX_LEASE_LABEL" {
	create_cred_script_with_env
	create_command_config "$TEST_TEMP_DIR/create-creds-env.sh"

	run "$FNOX_BIN" lease create test_cmd --duration 5m --format json --label my-label
	assert_success
	assert_output --partial '"DURATION_RECEIVED": "300"'
	assert_output --partial '"LABEL_RECEIVED": "my-label"'
}

@test "command backend: lease list shows created lease" {
	create_cred_script
	create_command_config

	run "$FNOX_BIN" lease create test_cmd --duration 15m --format json
	assert_success

	run "$FNOX_BIN" lease list --active
	assert_success
	assert_output --partial "test_cmd"
	assert_output --partial "active"
}

@test "command backend: lease revoke calls revoke_command" {
	create_cred_script
	create_revoke_script
	create_command_config "$TEST_TEMP_DIR/create-creds.sh" "$TEST_TEMP_DIR/revoke-creds.sh"

	# Create a lease
	run "$FNOX_BIN" lease create test_cmd --duration 15m --format json
	assert_success

	# Extract lease_id
	local lease_id
	lease_id=$(echo "$output" | grep -o '"lease_id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"lease_id"[[:space:]]*:[[:space:]]*"//;s/"$//')

	# Revoke it
	run "$FNOX_BIN" lease revoke "$lease_id"
	assert_success
	assert_output --partial "revoked"

	# Verify revoke script was called with the correct lease ID
	assert_file_exists "$TEST_TEMP_DIR/revoked.log"
	run cat "$TEST_TEMP_DIR/revoked.log"
	assert_output --partial "$lease_id"
}

@test "command backend: lease revoke without revoke_command succeeds silently" {
	create_cred_script
	create_command_config

	run "$FNOX_BIN" lease create test_cmd --duration 15m --format json
	assert_success

	local lease_id
	lease_id=$(echo "$output" | grep -o '"lease_id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"lease_id"[[:space:]]*:[[:space:]]*"//;s/"$//')

	run "$FNOX_BIN" lease revoke "$lease_id"
	assert_success
	assert_output --partial "revoked"
}

@test "command backend: create_command failure returns error" {
	create_failing_script
	create_command_config "$TEST_TEMP_DIR/fail.sh"

	run "$FNOX_BIN" lease create test_cmd --duration 15m --format json
	assert_failure
	assert_output --partial "something went wrong"
}

@test "command backend: invalid JSON output returns error" {
	create_bad_json_script
	create_command_config "$TEST_TEMP_DIR/bad-json.sh"

	run "$FNOX_BIN" lease create test_cmd --duration 15m --format json
	assert_failure
	assert_output --partial "Invalid JSON"
}

@test "command backend: missing credentials object returns error" {
	create_no_creds_script
	create_command_config "$TEST_TEMP_DIR/no-creds.sh"

	run "$FNOX_BIN" lease create test_cmd --duration 15m --format json
	assert_failure
	assert_output --partial "credentials"
}

@test "command backend: exec reuses cached lease on second run" {
	create_cred_script
	create_command_config

	# First exec creates the lease
	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "MY_TOKEN=tok-abc123"

	# Delete the script so the backend can't be called again
	rm "$TEST_TEMP_DIR/create-creds.sh"

	# Second exec should reuse cached credentials
	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "MY_TOKEN=tok-abc123"
}

@test "command backend: config change invalidates cached lease" {
	create_cred_script
	create_command_config

	# First exec creates the lease
	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "MY_TOKEN=tok-abc123"

	# Change the create_command (different config = different config_hash)
	cat >"$TEST_TEMP_DIR/create-creds2.sh" <<'SCRIPT'
#!/usr/bin/env bash
cat <<EOF
{
  "credentials": { "MY_TOKEN": "tok-NEW" },
  "expires_at": "2099-01-01T00:00:00Z",
  "lease_id": "cmd-test-lease-2"
}
EOF
SCRIPT
	chmod +x "$TEST_TEMP_DIR/create-creds2.sh"
	create_command_config "$TEST_TEMP_DIR/create-creds2.sh"

	# Should create a fresh lease with the new script (not reuse cache)
	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "MY_TOKEN=tok-NEW"
}

@test "command backend: cleanup with no expired leases" {
	create_cred_script
	create_command_config

	run "$FNOX_BIN" lease cleanup
	assert_success
	assert_output --partial "No expired leases"
}

@test "command backend: duration exceeding max fails" {
	create_cred_script
	create_command_config

	run "$FNOX_BIN" lease create test_cmd --duration 25h --format json
	assert_failure
	assert_output --partial "exceeds maximum"
}

@test "command backend: missing backend name fails" {
	cat >"$FNOX_CONFIG_FILE" <<'EOF'
root = true
EOF

	run "$FNOX_BIN" lease create nonexistent --duration 15m
	assert_failure
	assert_output --partial "not found"
}
