#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox reencrypt encrypts with new recipients" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate first keypair
	local keygen_output1
	keygen_output1=$(age-keygen -o key1.txt 2>&1)
	local public_key1
	public_key1=$(echo "$keygen_output1" | grep "^Public key:" | cut -d' ' -f3)

	# Generate second keypair
	local keygen_output2
	keygen_output2=$(age-keygen -o key2.txt 2>&1)
	local public_key2
	public_key2=$(echo "$keygen_output2" | grep "^Public key:" | cut -d' ' -f3)

	# Encrypt with first recipient only
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key1"]

[secrets]
EOF

	assert_fnox_success set MY_SECRET "hello-world" --age-key-file key1.txt

	# Secret can be read by Key1 before reencrypt
	assert_fnox_success get MY_SECRET --age-key-file key1.txt
	assert_output "hello-world"

	# Secret cannot be read by Key2 before reencrypt
	assert_fnox_failure get MY_SECRET --age-key-file key2.txt

	# Add second recipient and reencrypt
	perl -i -pe "s/recipients = \\[\"$public_key1\"\\]/recipients = [\"$public_key1\", \"$public_key2\"]/" fnox.toml
	assert_fnox_success reencrypt --force --age-key-file key1.txt

	# Secret can still be read by Key1
	assert_fnox_success get MY_SECRET --age-key-file key1.txt
	assert_output "hello-world"

	# Secret can now be read by Key2
	assert_fnox_success get MY_SECRET --age-key-file key2.txt
	assert_output "hello-world"
}

@test "fnox reencrypt works with secrets that use json_path" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate first keypair
	local keygen_output1
	keygen_output1=$(age-keygen -o key1.txt 2>&1)
	local public_key1
	public_key1=$(echo "$keygen_output1" | grep "^Public key:" | cut -d' ' -f3)

	# Generate second keypair
	local keygen_output2
	keygen_output2=$(age-keygen -o key2.txt 2>&1)
	local public_key2
	public_key2=$(echo "$keygen_output2" | grep "^Public key:" | cut -d' ' -f3)

	# Encrypt with first recipient only
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key1"]

[secrets]
EOF

	assert_fnox_success set JSON_SECRET '{"username":"admin","password":"secret123"}' --age-key-file key1.txt

	# Add json_path to the secret
	perl -i -pe 's/^(JSON_SECRET\s*=\s*\{.*)\}/$1, json_path = "username" }/' fnox.toml

	# Secret can be read by Key1 before reencrypt
	assert_fnox_success get JSON_SECRET --age-key-file key1.txt
	assert_output "admin"

	# Secret cannot be read by Key2 before reencrypt
	assert_fnox_failure get JSON_SECRET --age-key-file key2.txt

	# Add second recipient and reencrypt
	perl -i -pe "s/recipients = \\[\"$public_key1\"\\]/recipients = [\"$public_key1\", \"$public_key2\"]/" fnox.toml
	assert_fnox_success reencrypt --force --age-key-file key1.txt

	# Secret can still be read by Key1
	assert_fnox_success get JSON_SECRET --age-key-file key1.txt
	assert_output "admin"

	# Secret can now be read by Key2
	assert_fnox_success get JSON_SECRET --age-key-file key2.txt
	assert_output "admin"
}

require_age_keygen() {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi
}

secret_value() {
	local key="$1"
	local config_file="${2:-fnox.toml}"
	KEY="$key" perl -ne 'if (/^\Q$ENV{KEY}\E\s*=\s*\{.*?\bvalue\s*=\s*"([^"]+)"/) { print "$1\n"; exit }' "$config_file"
}

sync_value() {
	local key="$1"
	KEY="$key" perl -ne 'if (/^\Q$ENV{KEY}\E\s*=\s*\{.*?\bsync\s*=\s*\{\s*provider\s*=\s*"age"\s*,\s*value\s*=\s*"([^"]+)"/) { print "$1\n"; exit }' fnox.toml
}

assert_direct_age_secret() {
	local key="$1"
	local provider="$2"
	local config_file="${3:-fnox.toml}"
	local value
	value=$(secret_value "$key" "$config_file")
	[[ $value == fnox-age-batch-v1:* ]]
	grep -Eq "^${key}[[:space:]]*=[[:space:]]*\\{[[:space:]]*provider[[:space:]]*=[[:space:]]*\"${provider}\"" "$config_file"
}

batch_wrapper() {
	printf '%s\n' "${1%:*}"
}

@test "fnox reencrypt batches mixed age ciphertexts once per provider name" {
	require_age_keygen

	local public_key1 public_key2 other_public_key
	public_key1=$(age-keygen -o key1.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	public_key2=$(age-keygen -o key2.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	other_public_key=$(age-keygen -o other-key.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	grep "^AGE-SECRET-KEY" key1.txt >combined-keys.txt
	grep "^AGE-SECRET-KEY" other-key.txt >>combined-keys.txt

	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[providers.age]
type = "age"
recipients = ["$public_key1"]

[providers.other-age]
type = "age"
recipients = ["$other_public_key"]

[secrets]
FIRST = { provider = "source", value = "first", if_missing = "error" }
SECOND = { provider = "source", value = "second", if_missing = "error" }
OTHER = { provider = "source", value = "other", if_missing = "error" }
EOF

	# Seed a real shared batch, then make those cached values the direct source values.
	assert_fnox_success sync FIRST SECOND -p age --force --age-key-file key1.txt
	assert_fnox_success sync OTHER -p other-age --force --age-key-file key1.txt
	perl -i -pe 'if (/^(FIRST|SECOND|OTHER)\s*=\s*.*sync\s*=\s*\{\s*provider\s*=\s*"[^"]+"\s*,\s*value\s*=\s*"([^"]+)"\s*\}.*$/) { $_ = "$1 = { provider = \"" . ($1 eq "OTHER" ? "other-age" : "age") . "\", value = \"$2\", if_missing = \"error\" }\n" }' fnox.toml
	assert_direct_age_secret FIRST age
	assert_direct_age_secret SECOND age
	assert_direct_age_secret OTHER other-age
	assert_equal "$(batch_wrapper "$(secret_value FIRST)")" "$(batch_wrapper "$(secret_value SECOND)")"

	# Add a standalone ciphertext to the provider that already owns the shared batch.
	assert_fnox_success set THIRD "third" --provider age --age-key-file key1.txt
	perl -i -pe "s/recipients\\s*=\\s*\[\"$public_key1\"\]/recipients = [\"$public_key1\", \"$public_key2\"]/" fnox.toml
	assert_fnox_success reencrypt --force --age-key-file combined-keys.txt

	local first second third other
	first=$(secret_value FIRST)
	second=$(secret_value SECOND)
	third=$(secret_value THIRD)
	other=$(secret_value OTHER)
	[[ $first == fnox-age-batch-v1:* ]]
	[[ $other == fnox-age-batch-v1:* ]]
	assert_equal "$(batch_wrapper "$first")" "$(batch_wrapper "$second")"
	assert_equal "$(batch_wrapper "$first")" "$(batch_wrapper "$third")"
	[ "$(batch_wrapper "$first")" != "$(batch_wrapper "$other")" ]

	for key_file in key1.txt key2.txt; do
		assert_fnox_success get FIRST --age-key-file "$key_file"
		assert_output "first"
		assert_fnox_success get SECOND --age-key-file "$key_file"
		assert_output "second"
		assert_fnox_success get THIRD --age-key-file "$key_file"
		assert_output "third"
		assert_fnox_failure get OTHER --age-key-file "$key_file"
	done

	assert_fnox_failure get FIRST --age-key-file other-key.txt
	assert_fnox_failure get SECOND --age-key-file other-key.txt
	assert_fnox_failure get THIRD --age-key-file other-key.txt
	assert_fnox_success get OTHER --age-key-file other-key.txt
	assert_output "other"
}

@test "fnox reencrypt filters preserve unselected ciphertext" {
	require_age_keygen

	local public_key
	public_key=$(age-keygen -o key.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	cat >fnox.toml <<EOF
root = true
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$public_key"]

[providers.other-age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	assert_fnox_success set KEY_DEFAULT "default" --provider age --age-key-file key.txt
	assert_fnox_success set KEY_EXPLICIT "explicit" --provider age --age-key-file key.txt
	assert_fnox_success set FILTER_SELECTED "selected" --provider age --age-key-file key.txt
	assert_fnox_success set FILTER_OTHER "other" --provider other-age --age-key-file key.txt
	assert_fnox_success set SKIP_REGEX "skip" --provider age --age-key-file key.txt
	perl -i -pe 's/^(KEY_DEFAULT\s*=\s*\{\s*)provider\s*=\s*"age"\s*,\s*/$1/' fnox.toml
	[ -n "$(secret_value KEY_DEFAULT)" ]
	run grep -E '^KEY_DEFAULT[[:space:]]*=[[:space:]]*\{[[:space:]]*provider[[:space:]]*=' fnox.toml
	assert_failure

	local filter_selected_before filter_other_before skip_regex_before
	filter_selected_before=$(secret_value FILTER_SELECTED)
	filter_other_before=$(secret_value FILTER_OTHER)
	skip_regex_before=$(secret_value SKIP_REGEX)
	[ -n "$filter_selected_before" ]
	[ -n "$filter_other_before" ]
	[ -n "$skip_regex_before" ]
	assert_fnox_success reencrypt KEY_DEFAULT KEY_EXPLICIT --force --age-key-file key.txt
	assert_equal "$(batch_wrapper "$(secret_value KEY_DEFAULT)")" "$(batch_wrapper "$(secret_value KEY_EXPLICIT)")"
	assert_equal "$(secret_value FILTER_SELECTED)" "$filter_selected_before"
	assert_equal "$(secret_value FILTER_OTHER)" "$filter_other_before"
	assert_equal "$(secret_value SKIP_REGEX)" "$skip_regex_before"

	local key_default_after key_explicit_after
	key_default_after=$(secret_value KEY_DEFAULT)
	key_explicit_after=$(secret_value KEY_EXPLICIT)
	assert_fnox_success reencrypt --provider age --filter '^FILTER_' --force --age-key-file key.txt
	[ "$(secret_value FILTER_SELECTED)" != "$filter_selected_before" ]
	assert_equal "$(secret_value FILTER_OTHER)" "$filter_other_before"
	assert_equal "$(secret_value SKIP_REGEX)" "$skip_regex_before"
	assert_equal "$(secret_value KEY_DEFAULT)" "$key_default_after"
	assert_equal "$(secret_value KEY_EXPLICIT)" "$key_explicit_after"
}

@test "fnox reencrypt saves nothing when a provider batch fails" {
	require_age_keygen

	local public_key
	public_key=$(age-keygen -o key.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	cat >fnox.toml <<EOF
root = true

[providers.good-age]
type = "age"
recipients = ["$public_key"]

[providers.bad-age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

	assert_fnox_success set GOOD "good" --provider good-age --age-key-file key.txt
	assert_fnox_success set BROKEN "broken" --provider bad-age --age-key-file key.txt
	[ -n "$(secret_value GOOD)" ]
	[ -n "$(secret_value BROKEN)" ]
	perl -i -pe '$bad = 1 if /^\[providers\.bad-age\]/; if ($bad && /^recipients\s*=\s*/) { $_ = "recipients = [\"invalid\"]\n"; $bad = 0 }' fnox.toml
	cp fnox.toml fnox.toml.before

	assert_fnox_failure reencrypt --force --age-key-file key.txt
	assert_output --partial "BROKEN"
	assert_output --partial "bad-age"
	diff fnox.toml fnox.toml.before
}

@test "fnox reencrypt writes inherited and profile secrets to their source files" {
	if ! command -v age-keygen >/dev/null 2>&1 || ! command -v age >/dev/null 2>&1; then
		skip "age-keygen and age are required"
	fi

	local public_key1 public_key2 inherited_ciphertext explicit_ciphertext
	public_key1=$(age-keygen -o key1.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	public_key2=$(age-keygen -o key2.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	inherited_ciphertext=$(printf '%s' 'inherited' | age -r "$public_key1" | base64 | tr -d '\n')
	explicit_ciphertext=$(printf '%s' 'explicit' | age -r "$public_key1" | base64 | tr -d '\n')
	mkdir -p project/nested
	cat >project/fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key1", "$public_key2"]

[profiles.base]
default_provider = "age"

[profiles.base.secrets]
INHERITED = { value = "$inherited_ciphertext", if_missing = "error" }
EOF
	cat >project/nested/fnox.toml <<EOF
[profiles.development]
inherits = ["base"]

[profiles.development.secrets]
EXPLICIT = { provider = "age", value = "$explicit_ciphertext", if_missing = "error" }
EOF

	cd project/nested || exit 1
	assert_fnox_success --profile development reencrypt --force --age-key-file "$TEST_TEMP_DIR/key1.txt"
	local inherited explicit
	inherited=$(secret_value INHERITED ../fnox.toml)
	explicit=$(secret_value EXPLICIT fnox.toml)
	[[ $inherited == fnox-age-batch-v1:* ]]
	assert_equal "$(batch_wrapper "$inherited")" "$(batch_wrapper "$explicit")"
	refute grep -q '\[profiles\.development\.secrets\]' ../fnox.toml
	refute grep -q '\[profiles\.base\.secrets\]' fnox.toml

	assert_fnox_success --profile development get INHERITED --age-key-file "$TEST_TEMP_DIR/key2.txt"
	assert_output "inherited"
	assert_fnox_success --profile development get EXPLICIT --age-key-file "$TEST_TEMP_DIR/key2.txt"
	assert_output "explicit"
}

@test "fnox reencrypt resolves raw JSON and clears stale sync values" {
	require_age_keygen

	local public_key1 public_key2
	public_key1=$(age-keygen -o key1.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	public_key2=$(age-keygen -o key2.txt 2>&1 | grep "^Public key:" | cut -d' ' -f3)
	cat >fnox.toml <<EOF
root = true

[providers.source]
type = "plain"

[providers.age]
type = "age"
recipients = ["$public_key1"]

[secrets]
JSON_SECRET = { provider = "source", value = '{"username":"admin","password":"dummy"}', if_missing = "error" }
STALE_CACHE = { provider = "source", value = '{"username":"stale"}', if_missing = "error" }
EOF

	assert_fnox_success sync JSON_SECRET STALE_CACHE -p age --force --age-key-file key1.txt
	local json_ciphertext stale_ciphertext
	json_ciphertext=$(sync_value JSON_SECRET)
	stale_ciphertext=$(sync_value STALE_CACHE)
	[[ $json_ciphertext == fnox-age-batch-v1:* ]]
	[[ $stale_ciphertext == fnox-age-batch-v1:* ]]
	perl -i -pe "if (/^JSON_SECRET\\s*=/) { \$_ = qq{JSON_SECRET = { provider = \"age\", value = \"$json_ciphertext\", json_path = \"username\", description = \"account document\", sync = { provider = \"age\", value = \"$stale_ciphertext\" } }\n} } elsif (/^STALE_CACHE\\s*=/) { \$_ = \"\" }" fnox.toml
	assert_direct_age_secret JSON_SECRET age
	assert_equal "$(sync_value JSON_SECRET)" "$stale_ciphertext"
	run grep -E '^STALE_CACHE[[:space:]]*=' fnox.toml
	assert_failure
	perl -i -pe "s/recipients\\s*=\\s*\[\"$public_key1\"\]/recipients = [\"$public_key1\", \"$public_key2\"]/" fnox.toml

	assert_fnox_success reencrypt JSON_SECRET --force --age-key-file key1.txt
	run grep -E '^JSON_SECRET[[:space:]]*=.*sync[[:space:]]*=' fnox.toml
	assert_failure
	assert_config_contains 'JSON_SECRET.*json_path = "username"'
	assert_config_contains 'JSON_SECRET.*description = "account document"'
	assert_fnox_success get JSON_SECRET --age-key-file key2.txt
	assert_output "admin"
}
