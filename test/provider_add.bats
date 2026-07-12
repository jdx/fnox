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
	done <<<"$providers"

	run cat "$FNOX_CONFIG_FILE"
	assert_success
	while IFS='|' read -r provider_name _ expected_type; do
		assert_output --partial "[providers.$provider_name]"
		assert_output --partial "type = \"$expected_type\""
	done <<<"$providers"
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

@test "fnox provider add writes to top-level without --profile" {
	# Clear any inherited FNOX_PROFILE so provider add targets the top-level
	unset FNOX_PROFILE

	run "$FNOX_BIN" init --skip-wizard
	assert_success

	run "$FNOX_BIN" provider add myage age
	assert_success

	run cat "$FNOX_CONFIG_FILE"
	assert_success
	assert_output --partial "[providers.myage]"
}

@test "fnox provider add with --profile writes to profile section" {
	run "$FNOX_BIN" init --skip-wizard
	assert_success

	# Add a provider scoped to the prod profile
	run "$FNOX_BIN" -P prod provider add scoped age
	assert_success
	assert_output --partial "Added provider 'scoped'"

	# Provider should appear under [profiles.prod.providers.scoped]
	run cat "$FNOX_CONFIG_FILE"
	assert_success
	assert_output --partial "[profiles.prod.providers.scoped]"
	assert_output --partial 'type = "age"'

	# It should NOT be in the top-level [providers] section
	refute_output --partial "[providers.scoped]"
}

@test "fnox provider list shows composed providers from multiple profiles" {
	# Clear any inherited FNOX_PROFILE so the "no profile" case is deterministic
	unset FNOX_PROFILE

	run "$FNOX_BIN" init --skip-wizard
	assert_success

	# Top-level provider
	run "$FNOX_BIN" provider add base age
	assert_success

	# Profile-scoped provider
	run "$FNOX_BIN" -P extra provider add extra age
	assert_success

	# Without profile: only base visible
	run "$FNOX_BIN" provider list
	assert_success
	assert_output --partial "base"
	refute_output --partial "extra"

	# With extra profile: both visible
	run "$FNOX_BIN" -P extra provider list
	assert_success
	assert_output --partial "base"
	assert_output --partial "extra"
}
