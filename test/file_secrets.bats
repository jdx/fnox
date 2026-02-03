#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "exec with as_file=true creates temporary file" {
	# Create config with a plain provider secret marked as file
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = "my-secret-value", as_file = true }
EOF

	# Run exec command and verify file is created
	run "$FNOX_BIN" exec -- bash -c 'echo "File path: $MY_SECRET" && test -f "$MY_SECRET" && cat "$MY_SECRET"'
	assert_success
	assert_output --partial "File path:"
	assert_output --partial "my-secret-value"
	# Verify it's a file path (contains path separator)
	[[ ${lines[0]} == *"/"* ]]
}

@test "exec without as_file uses env var directly" {
	# Create config with a plain provider secret NOT marked as file
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = "my-secret-value" }
EOF

	# Run exec command and verify value is in env var
	run "$FNOX_BIN" exec -- bash -c 'echo "$MY_SECRET"'
	assert_success
	assert_output "my-secret-value"
}

@test "get with as_file=true returns file path" {
	# Create config with a plain provider secret marked as file
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = "my-secret-value", as_file = true }
EOF

	# Run get command and verify it returns a file path
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	# Output should be a file path (contains fnox-MY_SECRET in the name)
	assert_output --regexp "fnox-MY_SECRET-.*"

	# Verify the file exists and contains the secret
	local file_path="${output}"
	test -f "$file_path"
	[ "$(cat "$file_path")" = "my-secret-value" ]
}

@test "get without as_file returns secret value" {
	# Create config with a plain provider secret NOT marked as file
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = "my-secret-value" }
EOF

	# Run get command and verify it returns the value
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "my-secret-value"
}

@test "list shows file-based secrets with [file] indicator" {
	# Create config with both file and non-file secrets
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
FILE_SECRET = { provider = "plain", value = "file-value", as_file = true }
NORMAL_SECRET = { provider = "plain", value = "normal-value" }
EOF

	# Run list command and verify [file] indicator
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "FILE_SECRET"
	assert_output --partial "[file]"
	assert_output --partial "NORMAL_SECRET"
}

@test "exec with multiple file-based secrets creates multiple files" {
	# Create config with multiple file secrets
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
SECRET_1 = { provider = "plain", value = "value-1", as_file = true }
SECRET_2 = { provider = "plain", value = "value-2", as_file = true }
SECRET_3 = { provider = "plain", value = "value-3" }
EOF

	# Run exec command and verify all files are created
	run "$FNOX_BIN" exec -- bash -c 'test -f "$SECRET_1" && test -f "$SECRET_2" && echo "SECRET_1: $(cat "$SECRET_1")" && echo "SECRET_2: $(cat "$SECRET_2")" && echo "SECRET_3: $SECRET_3"'
	assert_success
	assert_output --partial "SECRET_1: value-1"
	assert_output --partial "SECRET_2: value-2"
	assert_output --partial "SECRET_3: value-3"
}

@test "file permissions are restricted (0600)" {
	# Skip on non-Unix systems
	if [[ $OSTYPE == "msys" || $OSTYPE == "cygwin" ]]; then
		skip "Permission test not applicable on Windows"
	fi

	# Create config with a file secret
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = "my-secret-value", as_file = true }
EOF

	# Get the file path
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	local file_path="${output}"

	# Check file permissions (should be 0600)
	local perms
	perms=$(stat -c "%a" "$file_path" 2>/dev/null || stat -f "%OLp" "$file_path" 2>/dev/null)
	[ "$perms" = "600" ]
}

@test "temp files are cleaned up after exec command exits" {
	# Create config with a file secret
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
MY_SECRET = { provider = "plain", value = "my-secret-value", as_file = true }
EOF

	# Run exec and capture the file path
	run "$FNOX_BIN" exec -- bash -c 'echo "$MY_SECRET"'
	assert_success
	local file_path="${output}"

	# File should not exist after command completes
	if [ -f "$file_path" ]; then
		echo "Temp file still exists: $file_path"
		return 1
	fi
}

@test "age-encrypted secret with as_file=true" {
	# Skip if age not installed
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

	# Create config with age provider
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	# Set a secret with as_file=true
	export FNOX_AGE_KEY=$private_key
	run "$FNOX_BIN" set MY_SECRET "encrypted-secret-value"
	assert_success

	# Manually add as_file to the config using perl for better compatibility
	perl -i.bak -pe 's/MY_SECRET= \{ /MY_SECRET= { as_file = true, /' fnox.toml

	# Verify it's encrypted
	assert_config_contains "MY_SECRET"
	assert_config_not_contains "encrypted-secret-value"
	assert_config_contains "as_file = true"

	# Get should return a file path
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output --regexp "fnox-MY_SECRET-.*"

	# Verify the file contains the decrypted value
	local file_path="${output}"
	[ "$(cat "$file_path")" = "encrypted-secret-value" ]
}

@test "multiline secret with as_file=true" {
	# Create config with a multiline secret
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	# Set a multiline secret using a heredoc
	local multiline_value
	multiline_value=$(
		cat <<'MULTILINE'
line1
line2
line3
MULTILINE
	)
	run "$FNOX_BIN" set MY_SECRET "$multiline_value"
	assert_success

	# Manually add as_file to the config using perl for better compatibility
	perl -i.bak -pe 's/MY_SECRET= \{ /MY_SECRET= { as_file = true, /' fnox.toml

	# Get should return a file path
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	local file_path="${output}"

	# Verify the file contains all lines
	local content
	content=$(cat "$file_path")
	[ "$content" = "$multiline_value" ]
}

@test "hook-env creates persistent temp files for file-based secrets" {
	# Skip if not in an interactive shell environment
	if [ -z "$SHELL" ]; then
		skip "SHELL environment variable not set"
	fi

	# Create config with a file-based secret
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
FILE_SECRET = { provider = "plain", value = "file-secret-value", as_file = true }
NORMAL_SECRET = { provider = "plain", value = "normal-value" }
EOF

	# Run hook-env to get shell code
	run "$FNOX_BIN" hook-env --shell bash
	assert_success

	# The output should contain export statements
	assert_output --partial "export FILE_SECRET="
	assert_output --partial "export NORMAL_SECRET="

	# Extract the FILE_SECRET value (should be a file path)
	local file_path
	file_path=$(echo "$output" | grep "export FILE_SECRET=" | sed -E 's/^export FILE_SECRET=\"(.*)\"$/\1/' | head -1)

	# Verify it looks like a file path
	[[ $file_path == *"fnox-hook-FILE_SECRET"* ]]
}

@test "hook-env cleans up old temp files when secrets change" {
	# Skip if not in an interactive shell environment
	if [ -z "$SHELL" ]; then
		skip "SHELL environment variable not set"
	fi

	# Create config with a file-based secret
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
FILE_SECRET = { provider = "plain", value = "first-value", as_file = true }
EOF

	# First invocation - creates temp file
	run "$FNOX_BIN" hook-env --shell bash
	assert_success
	local first_output
	first_output="$output"

	# Extract the session variable from output
	local session_var
	session_var=$(echo "$first_output" | grep "export __FNOX_SESSION=" | sed -E 's/^export __FNOX_SESSION=\"(.*)\"$/\1/')

	# Extract first file path
	local first_file
	first_file=$(echo "$first_output" | grep "export FILE_SECRET=" | sed -E 's/^export FILE_SECRET=\"(.*)\"$/\1/' | head -1)

	# Change the secret value
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
FILE_SECRET = { provider = "plain", value = "second-value", as_file = true }
EOF
	# Ensure config mtime changes so hook-env doesn't early-exit
	sleep 1
	# Force hook-env to run by changing an FNOX_* env var
	export FNOX_TEST_HOOK_ENV=1

	# Second invocation with previous session - should create new file and clean up old one
	export __FNOX_SESSION
	__FNOX_SESSION="$session_var"
	run "$FNOX_BIN" hook-env --shell bash
	assert_success
	local second_output="$output"

	# Extract second file path
	local second_file
	second_file=$(echo "$second_output" | grep "export FILE_SECRET=" | sed -E 's/^export FILE_SECRET=\"(.*)\"$/\1/' | head -1)

	# Second file should exist
	[ -n "$second_file" ]
	test -f "$second_file"

	# Old file should eventually be cleaned up (allow a short grace period)
	for _ in 1 2 3; do
		if [ ! -f "$first_file" ]; then
			break
		fi
		sleep 0.2
	done

	if [ -f "$first_file" ]; then
		echo "Old temp file still exists after hook-env update: $first_file"
		return 1
	fi
}

@test "export with as_file=true creates persistent file paths" {
	# Create config with file-based secrets
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
FILE_SECRET = { provider = "plain", value = "file-secret-value", as_file = true }
NORMAL_SECRET = { provider = "plain", value = "normal-value" }
EOF

	# Export to env format
	run "$FNOX_BIN" export --format env
	assert_success

	# Output should contain export statements
	assert_output --partial "export FILE_SECRET="
	assert_output --partial "export NORMAL_SECRET="

	# FILE_SECRET should be a file path (contains fnox-export)
	assert_output --regexp "export FILE_SECRET='.*/fnox-export-FILE_SECRET-.*'"

	# NORMAL_SECRET should be the actual value
	assert_output --partial "export NORMAL_SECRET='normal-value'"

	# Extract the file path and verify it exists
	local file_path
	file_path=$(echo "$output" | grep "export FILE_SECRET=" | sed "s/export FILE_SECRET='//" | sed "s/'//g")
	test -f "$file_path"
	[ "$(cat "$file_path")" = "file-secret-value" ]
}

@test "export to JSON with file-based secrets" {
	# Create config with file-based secret
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
FILE_SECRET = { provider = "plain", value = "file-value", as_file = true }
EOF

	# Export to JSON format
	run "$FNOX_BIN" export --format json
	assert_success

	# Output should be valid JSON
	echo "$output" | jq . >/dev/null

	# Extract the FILE_SECRET value (should be a file path)
	local file_path
	file_path=$(echo "$output" | jq -r '.secrets.FILE_SECRET')
	[[ $file_path == *"fnox-export-FILE_SECRET"* ]]

	# Verify file exists and contains the secret
	test -f "$file_path"
	[ "$(cat "$file_path")" = "file-value" ]
}

@test "export to file with file-based secrets" {
	# Create config
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
FILE_SECRET = { provider = "plain", value = "file-value", as_file = true }
NORMAL_SECRET = { provider = "plain", value = "normal-value" }
EOF

	# Export to a file
	local export_file="exported-secrets.env"
	run "$FNOX_BIN" export --format env --output "$export_file"
	assert_success
	assert_output --partial "Secrets exported to: $export_file"

	# Verify export file exists and contains file paths
	test -f "$export_file"
	grep -q "export FILE_SECRET=" "$export_file"
	grep -q "export NORMAL_SECRET='normal-value'" "$export_file"

	# Extract file path from export file
	local file_path
	file_path=$(grep "export FILE_SECRET=" "$export_file" | sed "s/export FILE_SECRET='//" | sed "s/'//g")
	test -f "$file_path"
	[ "$(cat "$file_path")" = "file-value" ]
}
