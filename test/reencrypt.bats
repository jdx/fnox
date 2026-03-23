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
