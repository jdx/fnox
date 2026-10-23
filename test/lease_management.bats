#!/usr/bin/env bats
#
# Lease Management Tests
#
# These tests verify `fnox lease list`, `revoke`, and `cleanup` using the
# command lease backend. No external services are required.

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# Helper: create a script that mints a lease whose ID embeds the label, so
# several leases from one backend get distinct IDs sharing a common prefix.
# $1 = script name, $2 = ID prefix, $3 = expires_at (see past_timestamp)
create_cred_script() {
	cat >"$TEST_TEMP_DIR/$1" <<SCRIPT
#!/usr/bin/env bash
cat <<JSON
{
  "credentials": {"TOKEN": "tok-\$FNOX_LEASE_LABEL"},
  "expires_at": "$3",
  "lease_id": "$2-\$FNOX_LEASE_LABEL"
}
JSON
SCRIPT
	chmod +x "$TEST_TEMP_DIR/$1"
}

# Helper: an RFC 3339 timestamp one hour ago (GNU and BSD date)
past_timestamp() {
	date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
		date -u -v-1H +%Y-%m-%dT%H:%M:%SZ
}

# Helper: create a revoke script that logs the lease ID
create_revoke_script() {
	cat >"$TEST_TEMP_DIR/revoke.sh" <<SCRIPT
#!/usr/bin/env bash
echo "\$FNOX_LEASE_ID" >> "$TEST_TEMP_DIR/revoked.log"
SCRIPT
	chmod +x "$TEST_TEMP_DIR/revoke.sh"
}

# Helper: config with backends alpha and beta, both logging revocations
create_config() {
	create_cred_script alpha.sh alpha "2099-01-01T00:00:00Z"
	create_cred_script beta.sh beta "2099-01-01T00:00:00Z"
	create_revoke_script
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.alpha]
type = "command"
create_command = "$TEST_TEMP_DIR/alpha.sh"
revoke_command = "$TEST_TEMP_DIR/revoke.sh"

[leases.beta]
type = "command"
create_command = "$TEST_TEMP_DIR/beta.sh"
revoke_command = "$TEST_TEMP_DIR/revoke.sh"
EOF
}

create_lease() {
	run "$FNOX_BIN" lease create "$1" --duration 15m --label "$2" --format json
	assert_success
}

@test "lease list --json prints an empty array with no leases" {
	create_config

	run "$FNOX_BIN" lease list --json
	assert_success
	assert_output "[]"
}

@test "lease list --json prints full IDs, labels, and status" {
	create_config
	create_lease alpha first-lease-with-a-long-label

	run "$FNOX_BIN" lease list --json
	assert_success
	echo "$output" | jq -e '
		length == 1
		and .[0].lease_id == "alpha-first-lease-with-a-long-label"
		and .[0].backend == "alpha"
		and .[0].label == "first-lease-with-a-long-label"
		and .[0].status == "active"
		and (.[0].created_at | type == "string")
		and (.[0].expires_at | startswith("2099-01-01T00:00:00"))
	'
	refute_output --partial "tok-"
}

@test "lease list --json respects --active" {
	create_config
	create_lease alpha one
	create_lease beta two
	run "$FNOX_BIN" lease revoke alpha-one
	assert_success

	run "$FNOX_BIN" lease list --json --active
	assert_success
	echo "$output" | jq -e 'length == 1 and .[0].lease_id == "beta-two"'

	run "$FNOX_BIN" lease list --json
	assert_success
	echo "$output" | jq -e 'length == 2'
}

@test "lease list table shows a label column" {
	create_config
	create_lease alpha my-purpose

	run "$FNOX_BIN" lease list
	assert_success
	assert_output --partial "LABEL"
	assert_output --partial "my-purpose"
}

@test "lease revoke accepts a full lease ID" {
	create_config
	create_lease alpha one

	run "$FNOX_BIN" lease revoke alpha-one
	assert_success
	assert_output --partial "Lease 'alpha-one' revoked."
	run cat "$TEST_TEMP_DIR/revoked.log"
	assert_output "alpha-one"
}

@test "lease revoke accepts a unique ID prefix" {
	create_config
	create_lease alpha one
	create_lease beta two

	run "$FNOX_BIN" lease revoke beta-t
	assert_success
	assert_output --partial "Lease 'beta-two' revoked."
	run cat "$TEST_TEMP_DIR/revoked.log"
	assert_output "beta-two"
}

@test "lease revoke accepts the shortened ID shown by lease list" {
	create_config
	create_lease alpha this-label-makes-the-lease-id-very-long

	run "$FNOX_BIN" lease list
	assert_success
	assert_output --partial "alpha-this-labe..."

	run "$FNOX_BIN" lease revoke "alpha-this-labe..."
	assert_success
	assert_output --partial "Lease 'alpha-this-label-makes-the-lease-id-very-long' revoked."
}

@test "lease revoke rejects an ambiguous prefix and lists the matches" {
	create_config
	create_lease alpha one
	create_lease beta two
	create_lease alpha other

	# "alpha-" is not a backend name but is a prefix of two lease IDs
	run "$FNOX_BIN" lease revoke "alpha-"
	assert_failure
	assert_output --partial "matches 2 leases"
	assert_output --partial "alpha-one"
	assert_output --partial "alpha-other"

	# Nothing was revoked
	assert_file_not_exist "$TEST_TEMP_DIR/revoked.log"
}

@test "lease revoke fails for an unknown lease" {
	create_config
	create_lease alpha one

	run "$FNOX_BIN" lease revoke nonexistent
	assert_failure
	assert_output --partial "not found"
}

@test "lease revoke by backend name revokes only that backend's active leases" {
	create_config
	create_lease alpha one
	create_lease alpha two
	create_lease beta three

	run "$FNOX_BIN" lease revoke alpha
	assert_success
	assert_output --partial "Lease 'alpha-one' revoked."
	assert_output --partial "Lease 'alpha-two' revoked."
	assert_output --partial "Revoked 2 lease(s)."

	run "$FNOX_BIN" lease list --json --active
	assert_success
	echo "$output" | jq -e 'length == 1 and .[0].lease_id == "beta-three"'

	run sort "$TEST_TEMP_DIR/revoked.log"
	assert_output "alpha-one
alpha-two"
}

@test "lease revoke by backend name with no active leases is a no-op" {
	create_config
	create_lease alpha one

	run "$FNOX_BIN" lease revoke beta
	assert_success
	assert_output --partial "No active leases to revoke."
	assert_file_not_exist "$TEST_TEMP_DIR/revoked.log"
}

@test "lease revoke --all revokes every active lease" {
	create_config
	create_lease alpha one
	create_lease beta two

	run "$FNOX_BIN" lease revoke --all
	assert_success
	assert_output --partial "Revoked 2 lease(s)."

	run "$FNOX_BIN" lease list --json --active
	assert_success
	assert_output "[]"

	run sort "$TEST_TEMP_DIR/revoked.log"
	assert_output "alpha-one
beta-two"
}

@test "lease revoke --all revokes every record when lease IDs are duplicated" {
	create_config
	# Both backends hand out the same lease ID
	create_cred_script alpha.sh shared "2099-01-01T00:00:00Z"
	create_cred_script beta.sh shared "2099-01-01T00:00:00Z"
	create_lease alpha same
	create_lease beta same

	run "$FNOX_BIN" lease revoke --all
	assert_success
	assert_output --partial "Revoked 2 lease(s)."

	run "$FNOX_BIN" lease list --json --active
	assert_success
	assert_output "[]"
	run cat "$TEST_TEMP_DIR/revoked.log"
	assert_output "shared-same
shared-same"
}

@test "lease revoke by backend name leaves another backend's duplicate ID active" {
	create_config
	create_cred_script alpha.sh shared "2099-01-01T00:00:00Z"
	create_cred_script beta.sh shared "2099-01-01T00:00:00Z"
	create_lease alpha same
	create_lease beta same

	run "$FNOX_BIN" lease revoke beta
	assert_success

	run "$FNOX_BIN" lease list --json
	assert_success
	echo "$output" | jq -e '
		(map(select(.backend == "alpha"))[0].status == "active")
		and (map(select(.backend == "beta"))[0].status == "revoked")
	'
}

@test "lease revoke --all with no active leases is a no-op" {
	create_config

	run "$FNOX_BIN" lease revoke --all
	assert_success
	assert_output --partial "No active leases to revoke."
}

@test "lease revoke requires a target or --all" {
	create_config

	run "$FNOX_BIN" lease revoke
	assert_failure
	assert_output --partial "--all"
}

@test "lease revoke rejects a target combined with --all" {
	create_config
	create_lease alpha one

	run "$FNOX_BIN" lease revoke alpha --all
	assert_failure
	assert_output --partial "--all cannot be used"
}

@test "lease revoke on an already revoked lease reports it" {
	create_config
	create_lease alpha one
	run "$FNOX_BIN" lease revoke alpha-one
	assert_success

	run "$FNOX_BIN" lease revoke alpha-one
	assert_success
	assert_output --partial "already revoked"
}

@test "lease revoke still revokes the ledger entry when the backend is gone" {
	create_config
	create_lease alpha one

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.beta]
type = "command"
create_command = "$TEST_TEMP_DIR/beta.sh"
EOF

	run "$FNOX_BIN" lease revoke alpha-one
	assert_success
	assert_output --partial "not found in config"
	assert_output --partial "Lease 'alpha-one' revoked."
}

@test "lease cleanup revokes expired leases and leaves active ones" {
	create_config
	create_cred_script alpha.sh alpha "$(past_timestamp)"
	create_lease alpha old
	create_cred_script alpha.sh alpha "2099-01-01T00:00:00Z"
	create_lease alpha fresh

	run "$FNOX_BIN" lease list --json
	assert_success
	echo "$output" | jq -e '
		(map(select(.lease_id == "alpha-old"))[0].status == "expired")
		and (map(select(.lease_id == "alpha-fresh"))[0].status == "active")
	'

	run "$FNOX_BIN" lease cleanup
	assert_success
	assert_output --partial "Cleaned up 1 expired lease(s)."

	run cat "$TEST_TEMP_DIR/revoked.log"
	assert_output "alpha-old"

	run "$FNOX_BIN" lease list --json
	assert_success
	echo "$output" | jq -e '
		(map(select(.lease_id == "alpha-old"))[0].status == "revoked")
		and (map(select(.lease_id == "alpha-fresh"))[0].status == "active")
	'
}

@test "lease cleanup revokes only the expired record when lease IDs are duplicated" {
	create_config
	create_cred_script alpha.sh shared "$(past_timestamp)"
	create_cred_script beta.sh shared "2099-01-01T00:00:00Z"
	create_lease alpha same
	create_lease beta same

	run "$FNOX_BIN" lease cleanup
	assert_success
	assert_output --partial "Cleaned up 1 expired lease(s)."

	run "$FNOX_BIN" lease list --json
	assert_success
	echo "$output" | jq -e '
		(map(select(.backend == "alpha"))[0].status == "revoked")
		and (map(select(.backend == "beta"))[0].status == "active")
	'
}

@test "lease revoke refuses an ID or prefix shared by several backends" {
	create_config
	create_cred_script alpha.sh shared "2099-01-01T00:00:00Z"
	create_cred_script beta.sh shared "2099-01-01T00:00:00Z"
	create_lease alpha same
	create_lease beta same

	run "$FNOX_BIN" lease revoke shared-same
	assert_failure
	assert_output --partial "is used by backends"

	run "$FNOX_BIN" lease revoke "shared-"
	assert_failure
	assert_output --partial "is used by backends"

	run "$FNOX_BIN" lease list --json --active
	assert_success
	echo "$output" | jq -e 'length == 2'
	assert_file_not_exist "$TEST_TEMP_DIR/revoked.log"
}

@test "lease cleanup with nothing expired is a no-op" {
	create_config
	create_lease alpha one

	run "$FNOX_BIN" lease cleanup
	assert_success
	assert_output --partial "No expired leases to clean up."
	assert_file_not_exist "$TEST_TEMP_DIR/revoked.log"
}
