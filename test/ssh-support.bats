#!/usr/bin/env bats

load test_helper/common_setup

setup() {
	_common_setup
}

@test "age provider supports SSH keys for decryption" {
	# Create a temporary directory for test keys
	local tmpdir
	tmpdir=$(mktemp -d)
	cd "$tmpdir"

	# Generate a test SSH key (Ed25519)
	ssh-keygen -t ed25519 -f test_ssh_key -N "" -C "test@example.com" >/dev/null 2>&1

	# Get SSH public key in format age expects
	local ssh_pubkey
	ssh_pubkey=$(cat test_ssh_key.pub)

	# Set up fnox config with age provider using SSH public key as recipient
	printf "[providers.age]\ntype = \"age\"\nrecipients = [\"%s\"]\n" "$ssh_pubkey" >fnox.toml

	# Test encrypting to SSH public key and decrypting with SSH private key
	run "$FNOX_BIN" set SSH_TEST "ssh-test-value" --provider age --age-key-file test_ssh_key
	assert_success
	assert_output --partial "Set secret SSH_TEST"

	# Try to decrypt with SSH private key (should work now)
	run "$FNOX_BIN" get SSH_TEST --age-key-file test_ssh_key
	assert_success
	assert_output "ssh-test-value"
}

@test "age provider supports password-protected SSH keys" {
	skip "Password-protected SSH keys require interactive prompts which bats cannot handle"
}
