#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Create a clean test config with age provider (no import)
	AGE_KEY=$(age-keygen 2>&1 | grep "^AGE-SECRET-KEY" || true)
	AGE_PUB=$(echo "$AGE_KEY" | age-keygen -y 2>/dev/null || true)

	# Create a completely fresh config file with root=true to prevent parent lookup
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$AGE_PUB"]
EOF

	# Store the age key for decryption
	mkdir -p "$HOME/.config/fnox"
	echo "$AGE_KEY" >"$HOME/.config/fnox/age.txt"
}

teardown() {
	_common_teardown
}

@test "secrets preserve insertion order when using fnox set" {
	# Set 5 secrets in a specific order
	run fnox set FIRST_SECRET "value1" --provider age
	assert_success

	run fnox set SECOND_SECRET "value2" --provider age
	assert_success

	run fnox set THIRD_SECRET "value3" --provider age
	assert_success

	run fnox set FOURTH_SECRET "value4" --provider age
	assert_success

	run fnox set FIFTH_SECRET "value5" --provider age
	assert_success

	# Read the config file and extract secrets from the [secrets] section
	# With inline table format, secrets look like: SECRET_NAME= { provider = "age", value = "..." }
	# Use awk to extract secrets between [secrets] and next section (or EOF)
	secrets_section=$(awk '
		/^\[secrets\]$/ { in_secrets=1; next }
		/^\[/ && in_secrets { in_secrets=0 }
		in_secrets && /^(FIRST|SECOND|THIRD|FOURTH|FIFTH)_SECRET\s*=/ { print }
	' fnox.toml)

	# Extract just the keys in the order they appear (handle both "KEY=" and "KEY =")
	keys=$(echo "$secrets_section" | sed 's/^\([A-Z_]*\)\s*=.*/\1/' | tr '\n' ' ')

	# Verify the order
	expected_order="FIRST_SECRET SECOND_SECRET THIRD_SECRET FOURTH_SECRET FIFTH_SECRET "
	assert_equal "$keys" "$expected_order"
}

@test "secrets preserve order when modifying existing secrets" {
	# Set initial secrets in order
	fnox set ALPHA "a" --provider age
	fnox set BETA "b" --provider age
	fnox set GAMMA "c" --provider age
	fnox set DELTA "d" --provider age

	# Modify the second secret
	run fnox set BETA "b_modified" --provider age
	assert_success

	# Extract keys from config using inline table format
	secrets_section=$(awk '
		/^\[secrets\]$/ { in_secrets=1; next }
		/^\[/ && in_secrets { in_secrets=0 }
		in_secrets && /^(ALPHA|BETA|GAMMA|DELTA)\s*=/ { print }
	' fnox.toml)
	keys=$(echo "$secrets_section" | sed 's/^\([A-Z_]*\)\s*=.*/\1/' | tr '\n' ' ')

	# Order should be preserved (BETA stays in second position)
	expected_order="ALPHA BETA GAMMA DELTA "
	assert_equal "$keys" "$expected_order"
}

@test "fnox list shows secrets in insertion order" {
	# Set secrets in a specific order
	fnox set ZEBRA "z" --provider age
	fnox set YANKEE "y" --provider age
	fnox set XRAY "x" --provider age
	fnox set WHISKEY "w" --provider age
	fnox set VICTOR "v" --provider age

	# List secrets - should NOT be alphabetically sorted, but in insertion order
	run fnox list --complete
	assert_success

	# The output should preserve insertion order (Z, Y, X, W, V)
	assert_line --index 0 "ZEBRA"
	assert_line --index 1 "YANKEE"
	assert_line --index 2 "XRAY"
	assert_line --index 3 "WHISKEY"
	assert_line --index 4 "VICTOR"
}

@test "export preserves secret order" {
	# Set secrets in a specific order
	fnox set ONE "1" --provider age
	fnox set TWO "2" --provider age
	fnox set THREE "3" --provider age

	# Export as env format
	run fnox --age-key-file "$HOME/.config/fnox/age.txt" export --format env
	assert_success

	# Extract just the variable names in the order they appear
	keys=$(echo "$output" | grep "^export" | sed 's/export \([^=]*\)=.*/\1/' | tr '\n' ' ')

	expected_order="ONE TWO THREE "
	assert_equal "$keys" "$expected_order"
}
