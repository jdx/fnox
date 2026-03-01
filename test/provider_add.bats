#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox provider add supports all provider types" {
	# name|cli-type|serialized-type — single source of truth for all provider types
	local providers
	providers="onepass|1password|1password
agep|age|age
awssm|aws|aws-sm
awskms|aws-kms|aws-kms
awsps|aws-ps|aws-ps
azurekms|azure-kms|azure-kms
azuresm|azure-sm|azure-sm
gcpsm|gcp|gcp-sm
gcpkms|gcp-kms|gcp-kms
bitwarden|bitwarden|bitwarden
bws|bitwarden-sm|bitwarden-sm
infisical|infisical|infisical
keepass|keepass|keepass
keychain|keychain|keychain
passstore|password-store|password-store
passwordstate|passwordstate|passwordstate
plain|plain|plain
proton|proton-pass|proton-pass
vault|vault|vault"

	run "$FNOX_BIN" init --skip-wizard
	assert_success

	while IFS='|' read -r provider_name provider_type expected_type; do
		run "$FNOX_BIN" provider add "$provider_name" "$provider_type"
		assert_success
		assert_output --partial "Added provider '$provider_name'"
	done <<< "$providers"

	run cat "$FNOX_CONFIG_FILE"
	assert_success
	while IFS='|' read -r provider_name _ expected_type; do
		assert_output --partial "[providers.$provider_name]"
		assert_output --partial "type = \"$expected_type\""
	done <<< "$providers"
}

@test "fnox provider add creates Proton Pass provider config" {
	run "$FNOX_BIN" init --skip-wizard
	assert_success

	run "$FNOX_BIN" provider add mypass proton-pass
	assert_success

	run cat "$FNOX_CONFIG_FILE"
	assert_success
	assert_output --partial "[providers.mypass]"
	assert_output --partial 'type = "proton-pass"'
}

@test "fnox provider add with vault creates proper config" {
	run "$FNOX_BIN" init --skip-wizard
	assert_success

	run "$FNOX_BIN" provider add mypass proton-pass --vault "MyVault"
	assert_success

	run cat "$FNOX_CONFIG_FILE"
	assert_success
	assert_output --partial "[providers.mypass]"
	assert_output --partial 'type = "proton-pass"'
	assert_output --partial 'vault = "MyVault"'
}

@test "fnox provider add --vault fails for non-proton provider types" {
	run "$FNOX_BIN" init --skip-wizard
	assert_success

	run "$FNOX_BIN" provider add myage age --vault "bad-vault"
	assert_failure
	assert_output --partial "--vault is only supported for provider type"
}
