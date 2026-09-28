#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# Helper function to setup two age providers and secrets for sync testing
setup_sync_env() {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	local private_key
	private_key=$(grep "^AGE-SECRET-KEY" key.txt)

	export FNOX_AGE_KEY="$private_key"

	# Create config with two age providers (source-age simulates a "remote" provider)
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[providers.source-age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	# Use fnox set to properly create encrypted secrets with source-age provider
	run "$FNOX_BIN" set MY_SECRET "remote-secret-value" --provider source-age
	assert_success
	run "$FNOX_BIN" set ANOTHER_SECRET "another-remote-value" --provider source-age
	assert_success
	# Create one already using the target provider
	run "$FNOX_BIN" set ALREADY_AGE "already-encrypted" --provider age
	assert_success

	# Add a plain default-only secret (no provider) by appending to config
	echo 'PLAIN_VAR = { default = "plain-value" }' >>fnox.toml
}

@test "fnox sync basic: syncs remote secrets to local encryption provider" {
	setup_sync_env

	# Sync from source-age to age
	assert_fnox_success sync -p age --force

	# Verify the synced secrets can be decrypted
	assert_fnox_success get MY_SECRET --age-key-file key.txt
	assert_output "remote-secret-value"

	assert_fnox_success get ANOTHER_SECRET --age-key-file key.txt
	assert_output "another-remote-value"
}

@test "fnox sync skips secrets already using target provider" {
	setup_sync_env

	# Sync to age - ALREADY_AGE should be skipped
	assert_fnox_success sync -p age --force

	# ALREADY_AGE should still be decryptable
	assert_fnox_success get ALREADY_AGE --age-key-file key.txt
	assert_output "already-encrypted"

	# MY_SECRET and ANOTHER_SECRET should be synced
	assert_fnox_success get MY_SECRET --age-key-file key.txt
	assert_output "remote-secret-value"
}

@test "fnox sync skips secrets without providers" {
	setup_sync_env

	# PLAIN_VAR has no provider (only a default), should be skipped
	assert_fnox_success sync -p age --force

	# PLAIN_VAR should still work with its default
	assert_fnox_success get PLAIN_VAR
	assert_output "plain-value"
}

@test "fnox sync --dry-run shows what would be synced without changes" {
	setup_sync_env

	# Save original config
	cp fnox.toml fnox.toml.orig

	assert_fnox_success sync -p age --dry-run
	assert_output --partial "[dry-run]"
	assert_output --partial "Would sync"
	assert_output --partial "MY_SECRET"
	assert_output --partial "ANOTHER_SECRET"
	# ALREADY_AGE and PLAIN_VAR should not be listed
	refute_output --partial "ALREADY_AGE"
	refute_output --partial "PLAIN_VAR"

	# Verify config was NOT modified
	diff fnox.toml fnox.toml.orig
}

@test "fnox sync -n is alias for --dry-run" {
	setup_sync_env

	cp fnox.toml fnox.toml.orig

	assert_fnox_success sync -p age -n
	assert_output --partial "[dry-run]"

	diff fnox.toml fnox.toml.orig
}

@test "fnox sync --dry-run --local-file shows marker without creating file" {
	setup_sync_env

	cp fnox.toml fnox.toml.orig

	assert_fnox_success sync -p age --dry-run --local-file
	assert_output --partial "[dry-run]"
	assert_output --partial "(local-file)"
	assert_output --partial "MY_SECRET"
	assert_output --partial "ANOTHER_SECRET"

	[ ! -f fnox.local.toml ]
	diff fnox.toml fnox.toml.orig
}

@test "fnox sync --local-file writes sync overrides to fnox.local.toml" {
	setup_sync_env

	cp fnox.toml fnox.toml.orig

	assert_fnox_success sync -p age --local-file --force

	# Sync cache should be written to fnox.local.toml only
	[ -f fnox.local.toml ]
	run grep 'sync = { provider = "age", value = "' fnox.local.toml
	assert_success

	run grep 'sync = {' fnox.toml
	assert_failure
	diff fnox.toml fnox.toml.orig

	# Merged loading should still resolve via local override
	assert_fnox_success get MY_SECRET --age-key-file key.txt
	assert_output "remote-secret-value"
}

@test "fnox sync --local-file refreshes from updated source config" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export FNOX_AGE_KEY
	FNOX_AGE_KEY=$(grep "^AGE-SECRET-KEY" key.txt)

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[secrets]
MY_SECRET = { provider = "source", value = "first", if_missing = "error" }
EOF
	cat >fnox.local.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]
EOF

	assert_fnox_success sync -p age --local-file --force
	assert_fnox_success get MY_SECRET
	assert_output "first"

	sed -i.bak 's/value = "first"/value = "second"/' fnox.toml
	assert_fnox_success sync -p age --local-file --force
	assert_fnox_success get MY_SECRET
	assert_output "second"

	sed -i.bak '/MY_SECRET =/d' fnox.toml
	assert_fnox_success sync -p age --local-file --force
	assert_output --partial "Removed 1 stale entries from the local cache"
	run grep 'MY_SECRET' fnox.local.toml
	assert_failure
}

@test "fnox sync --local-file resolves provider secret references from updated source config" {
	if ! command -v age-keygen >/dev/null 2>&1 || ! command -v age >/dev/null 2>&1; then
		skip "age-keygen and age are required"
	fi

	local source_public_key
	source_public_key=$(age-keygen -o source-key.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	local cache_public_key
	cache_public_key=$(age-keygen -o cache-key.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	local first_ciphertext
	first_ciphertext=$(printf '%s' 'first' | age -r "$source_public_key" | base64 | tr -d '\n')

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[providers.source-age]
type = "age"
recipients = ["$source_public_key"]
key_file = { secret = "SOURCE_KEY_FILE" }

[secrets]
SOURCE_KEY_FILE = { provider = "source", value = "source-key.txt", if_missing = "error" }
MY_SECRET = { provider = "source-age", value = "$first_ciphertext", if_missing = "error" }
EOF
	cat >fnox.local.toml <<EOF
[providers.cache-age]
type = "age"
recipients = ["$cache_public_key"]
key_file = { secret = "CACHE_KEY_FILE" }

[secrets]
CACHE_KEY_FILE = { default = "cache-key.txt" }
EOF

	assert_fnox_success sync -p cache-age --local-file --force

	local next_source_public_key
	next_source_public_key=$(age-keygen -o next-source-key.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	local next_ciphertext
	next_ciphertext=$(printf '%s' 'second' | age -r "$next_source_public_key" | base64 | tr -d '\n')
	sed -i.bak 's|value = "source-key.txt"|value = "next-source-key.txt"|' fnox.toml
	sed -i.bak "s|recipients = \[\"$source_public_key\"\]|recipients = [\"$next_source_public_key\"]|" fnox.toml
	sed -i.bak "s|value = \"$first_ciphertext\"|value = \"$next_ciphertext\"|" fnox.toml

	assert_fnox_success sync -p cache-age --local-file --force
	assert_fnox_success get MY_SECRET
	assert_output "second"
}

@test "fnox sync --local-file keeps profile caches distinct" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export FNOX_AGE_KEY
	FNOX_AGE_KEY=$(grep "^AGE-SECRET-KEY" key.txt)

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[secrets]
MY_SECRET = { provider = "source", value = "default", if_missing = "error" }

[profiles.development.secrets]
MY_SECRET = { provider = "source", value = "development", if_missing = "error" }
EOF
	cat >fnox.local.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]
EOF

	assert_fnox_success sync -p age --local-file --force
	assert_fnox_success --profile development sync -p age --local-file --force
	assert_fnox_success --profile development get MY_SECRET
	assert_output "development"

	sed -i.bak '/MY_SECRET =/d' fnox.toml
	assert_fnox_success --profile development sync -p age --local-file --force
	assert_output --partial "Removed 2 stale entries from the local cache"
	run grep 'MY_SECRET' fnox.local.toml
	assert_failure
}

@test "fnox sync --local-file preserves root local sources for profile refreshes" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export FNOX_AGE_KEY
	FNOX_AGE_KEY=$(grep "^AGE-SECRET-KEY" key.txt)

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[profiles.development]
EOF
	cat >fnox.local.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
LOCAL_SECRET = { provider = "source", value = "local", if_missing = "error" }
EOF

	assert_fnox_success --profile development sync -p age --local-file --force
	assert_fnox_success --profile development sync -p age --local-file --force
	assert_output --partial "Synced 1 secrets"
	run grep 'LOCAL_SECRET = { provider = "source"' fnox.local.toml
	assert_success
}

@test "fnox sync --local-file --no-defaults preserves default profile caches" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export FNOX_AGE_KEY
	FNOX_AGE_KEY=$(grep "^AGE-SECRET-KEY" key.txt)

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[secrets]
ROOT_SECRET = { provider = "source", value = "root", if_missing = "error" }

[profiles.development.secrets]
PROFILE_SECRET = { provider = "source", value = "profile", if_missing = "error" }

[profiles.development.providers.age]
type = "plain"
EOF
	cat >fnox.local.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]
EOF

	assert_fnox_success sync -p age --local-file --force
	assert_fnox_success --profile development --no-defaults sync -p age --local-file --force
	run grep 'ROOT_SECRET' fnox.local.toml
	assert_success
	run "$FNOX_BIN" --profile development --no-defaults get ROOT_SECRET
	assert_failure
}

@test "fnox sync --local-file removes stale inherited profile caches" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export FNOX_AGE_KEY
	FNOX_AGE_KEY=$(grep "^AGE-SECRET-KEY" key.txt)

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[profiles.base.secrets]
BASE_SECRET = { provider = "source", value = "base", if_missing = "error" }

[profiles.development]
inherits = ["base"]

[profiles.development.secrets]
PROFILE_SECRET = { provider = "source", value = "profile", if_missing = "error" }
EOF
	cat >fnox.local.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]
EOF

	assert_fnox_success --profile base sync -p age --local-file --force
	assert_fnox_success --profile development sync -p age --local-file --force
	sed -i.bak '/BASE_SECRET =/d' fnox.toml
	assert_fnox_success --profile development sync -p age --local-file --force
	assert_output --partial "Removed 2 stale entries from the local cache"
	run grep 'BASE_SECRET' fnox.local.toml
	assert_failure
}

@test "fnox sync --local-file preserves inherited caches shadowed by derived profiles" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export FNOX_AGE_KEY
	FNOX_AGE_KEY=$(grep "^AGE-SECRET-KEY" key.txt)

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[profiles.base.secrets]
SHARED_SECRET = { provider = "source", value = "base", if_missing = "error" }

[profiles.development]
inherits = ["base"]
EOF
	cat >fnox.local.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]
EOF

	assert_fnox_success --profile base sync -p age --local-file --force
	assert_fnox_success --profile development sync -p age --local-file --force
	cat >>fnox.toml <<EOF

[profiles.development.secrets]
SHARED_SECRET = { default = "development" }
EOF

	assert_fnox_success --profile development sync -p age --local-file --force
	assert_output --partial "Removed 1 stale entries from the local cache"
	run grep -c 'SHARED_SECRET' fnox.local.toml
	assert_success
	assert_output "1"
	assert_fnox_success --profile base get SHARED_SECRET
	assert_output "base"
	assert_fnox_success --profile development get SHARED_SECRET
	assert_output "development"
}

@test "fnox sync --local-file reconciles both local override filenames" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	export FNOX_AGE_KEY
	FNOX_AGE_KEY=$(grep "^AGE-SECRET-KEY" key.txt)

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[secrets]
MY_SECRET = { provider = "source", value = "first", if_missing = "error" }
EOF
	cat >fnox.local.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]
EOF

	assert_fnox_success sync -p age --local-file --force
	cp fnox.local.toml .fnox.local.toml
	sed -i.bak 's/value = "first"/value = "second"/' fnox.toml
	assert_fnox_success sync -p age --local-file --force
	assert_fnox_success get MY_SECRET
	assert_output "second"

	sed -i.bak '/MY_SECRET =/d' fnox.toml
	assert_fnox_success sync -p age --local-file --force
	assert_output --partial "Removed 2 stale entries from the local cache"
	run grep 'MY_SECRET' fnox.local.toml
	assert_failure
	run grep 'MY_SECRET' .fnox.local.toml
	assert_failure
}

@test "fnox sync --local-file uses same directory as --config file" {
	setup_sync_env

	mkdir -p nested
	mv fnox.toml nested/fnox.toml

	cd nested || exit 1

	run "$FNOX_BIN" --config fnox.toml sync -p age --local-file --force
	assert_success

	[ -f fnox.local.toml ]
	[ ! -f ../fnox.local.toml ]
	run grep 'sync = { provider = "age", value = "' fnox.local.toml
	assert_success

	run "$FNOX_BIN" --config fnox.toml get MY_SECRET --age-key-file ../key.txt
	assert_success
	assert_output "remote-secret-value"
}

@test "fnox sync --local-file uses .fnox.local.toml when default config is .fnox.toml" {
	setup_sync_env

	mv fnox.toml .fnox.toml

	run "$FNOX_BIN" sync -p age --local-file --force
	assert_success

	[ -f .fnox.local.toml ]
	[ ! -f fnox.local.toml ]
	run grep 'sync = { provider = "age", value = "' .fnox.local.toml
	assert_success

	run "$FNOX_BIN" get MY_SECRET --age-key-file key.txt
	assert_success
	assert_output "remote-secret-value"
}

@test "fnox sync --local-file round-trips with .fnox.toml" {
	setup_sync_env

	mv fnox.toml .fnox.toml

	run "$FNOX_BIN" --config .fnox.toml sync -p age --local-file --force
	assert_success

	[ -f .fnox.local.toml ]
	[ ! -f fnox.local.toml ]
	run grep 'sync = { provider = "age", value = "' .fnox.local.toml
	assert_success

	run "$FNOX_BIN" --config .fnox.toml get MY_SECRET --age-key-file key.txt
	assert_success
	assert_output "remote-secret-value"
}

@test "fnox sync --local-file fails with non-default --config filename" {
	setup_sync_env

	mkdir -p nested
	mv fnox.toml nested/custom.toml

	run "$FNOX_BIN" --config nested/custom.toml sync -p age --local-file --force
	assert_failure
	assert_output --partial "nested/custom.toml"
	[ ! -f nested/fnox.local.toml ]
}

@test "fnox sync --local-file rejects explicit default config paths" {
	setup_sync_env

	mkdir -p nested
	mv fnox.toml nested/fnox.toml

	run "$FNOX_BIN" --config nested/fnox.toml sync -p age --local-file --force
	assert_failure
	assert_output --partial "is an explicit"
	[ ! -f nested/fnox.local.toml ]
}

@test "fnox sync does not create parent directory for explicit default config path" {
	setup_sync_env

	run "$FNOX_BIN" --config nonexistent/fnox.toml sync -p age --force
	assert_failure
	assert_output --partial "Failed to read configuration file:"
	assert_output --partial "nonexistent/"
	assert_output --partial "fnox.toml"
	[ ! -d nonexistent ]
}

@test "fnox sync with --source filters by source provider" {
	setup_sync_env

	assert_fnox_success sync -p age --source source-age --dry-run
	assert_output --partial "MY_SECRET"
	assert_output --partial "ANOTHER_SECRET"

	# Non-existent source should find nothing
	assert_fnox_success sync -p age --source nonexistent --dry-run
	assert_output --partial "No secrets to sync"
}

@test "fnox sync with --filter filters by regex" {
	setup_sync_env

	assert_fnox_success sync -p age --filter "^MY_" --dry-run
	assert_output --partial "MY_SECRET"
	refute_output --partial "ANOTHER_SECRET"
}

@test "fnox sync with positional KEYS filters specific secrets" {
	setup_sync_env

	assert_fnox_success sync MY_SECRET -p age --dry-run
	assert_output --partial "MY_SECRET"
	refute_output --partial "ANOTHER_SECRET"
}

@test "fnox sync --local-file conflicts with --global" {
	setup_sync_env

	assert_fnox_failure sync -p age --local-file --global --force
	assert_output --partial "cannot be used with"
}

@test "fnox sync fails with invalid target provider" {
	setup_sync_env

	assert_fnox_failure sync -p nonexistent --force
	assert_output --partial "not configured"
}

@test "fnox sync fails when target provider lacks encryption capability" {
	setup_sync_env

	# Add a 1password provider (RemoteRead only, no encryption capability)
	cat >>fnox.toml <<EOF

[providers.op]
type = "1password"
EOF

	assert_fnox_failure sync -p op --force
	assert_output --partial "cannot be used as a sync target"
}

@test "fnox sync prompts for confirmation by default" {
	setup_sync_env

	# Answer 'n' to the confirmation prompt
	run bash -c "echo 'n' | $FNOX_BIN sync -p age"
	assert_output --partial "Continue? [y/N]"
	assert_output --partial "Sync cancelled"
}

@test "fnox sync preserves original provider in config" {
	setup_sync_env

	# Sync from source-age to age
	assert_fnox_success sync -p age --force

	# Verify original provider is preserved in the config
	run grep 'provider = "source-age"' fnox.toml
	assert_success

	# Verify sync field is present
	run grep 'sync = {' fnox.toml
	assert_success
}

@test "fnox sync writes sync field structure" {
	setup_sync_env

	# Sync from source-age to age
	assert_fnox_success sync -p age --force

	# Verify the TOML contains sync = { provider = "age", value = "..." }
	run grep 'sync = { provider = "age", value = "' fnox.toml
	assert_success
}

@test "fnox sync re-running refreshes values" {
	setup_sync_env

	# First sync
	assert_fnox_success sync -p age --force

	# Verify initial value
	assert_fnox_success get MY_SECRET --age-key-file key.txt
	assert_output "remote-secret-value"

	# Update the source secret
	run "$FNOX_BIN" set MY_SECRET "updated-remote-value" --provider source-age
	assert_success

	# Re-sync
	assert_fnox_success sync -p age --force

	# Verify updated value
	assert_fnox_success get MY_SECRET --age-key-file key.txt
	assert_output "updated-remote-value"
}

@test "fnox sync works with secrets that use json_path" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
DB_USER = { provider = "plain", value = '{"username":"admin","password":"secret123"}', json_path = "username" }
DB_PASS = { provider = "plain", value = '{"username":"admin","password":"secret123"}', json_path = "password" }
EOF

	# Pre-sync: json_path extraction works
	assert_fnox_success get DB_USER
	assert_output "admin"
	assert_fnox_success get DB_PASS
	assert_output "secret123"

	# Sync to age
	assert_fnox_success sync -p age --force --age-key-file key.txt

	# Post-sync: json_path extraction still works on the cached value
	assert_fnox_success get DB_USER --age-key-file key.txt
	assert_output "admin"
	assert_fnox_success get DB_PASS --age-key-file key.txt
	assert_output "secret123"
}

@test "fnox sync skips secrets that fall back to a default value" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
HAS_VALUE = { provider = "plain", value = "real-value" }
HAS_DEFAULT_ONLY = { provider = "plain", default = "fallback" }
EOF

	# Pre-sync: secrets can be resolved
	assert_fnox_success get HAS_VALUE
	assert_output "real-value"
	assert_fnox_success get HAS_DEFAULT_ONLY
	assert_output "fallback"

	# Sync — HAS_DEFAULT_ONLY should be skipped (no provider value to cache)
	assert_fnox_success sync -p age --force --age-key-file key.txt
	assert_output --partial "Skipped 1 secrets"

	# Post-sync: secrets can still be resolved
	assert_fnox_success get HAS_VALUE --age-key-file key.txt
	assert_output "real-value"
	assert_fnox_success get HAS_DEFAULT_ONLY
	assert_output "fallback"

	# HAS_VALUE should have a sync section in the config
	run grep 'HAS_VALUE.*sync' fnox.toml
	assert_success

	# HAS_DEFAULT_ONLY should not have a sync section in the config
	run grep 'HAS_DEFAULT_ONLY.*sync' fnox.toml
	assert_failure
}

@test "fnox sync with no eligible secrets shows message" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)

	# Config where all secrets already use the target provider
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
PLAIN_VAR = { default = "value" }
EOF

	assert_fnox_success sync -p age --force
	assert_output --partial "No secrets to sync"
}
