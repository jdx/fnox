#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
}

@test "fnox exec with if_missing=error fails on missing secret" {
	cat >fnox.toml <<'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
if_missing = "error"
TOML

	# Set invalid age key to trigger error
	export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

	run "$FNOX_BIN" exec -- echo "should not run"
	assert_failure
}

@test "fnox exec with if_missing=warn continues on missing secret" {
	cat >fnox.toml <<'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
if_missing = "warn"
TOML

	# Set invalid age key to trigger error
	export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

	run "$FNOX_BIN" exec -- echo "command succeeded"
	assert_success
	assert_output --partial "command succeeded"
}

@test "fnox exec with default if_missing (warn) continues on missing secret" {
	cat >fnox.toml <<'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

	# Set invalid age key to trigger error
	export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

	run "$FNOX_BIN" exec -- echo "command succeeded"
	assert_success
	assert_output --partial "command succeeded"
}

@test "fnox exec with if_missing=ignore silently continues on missing secret" {
	cat >fnox.toml <<'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
if_missing = "ignore"
TOML

	# Set invalid age key to trigger error
	export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

	run "$FNOX_BIN" exec -- echo "command succeeded"
	assert_success
	assert_output --partial "command succeeded"
}

# A provider whose own settings don't resolve can't serve any secret, so
# if_missing (which is about a missing key) doesn't hide it.
@test "fnox exec fails when a provider's own settings don't resolve, whatever if_missing is" {
	for mode in ignore warn; do
		cat >fnox.toml <<TOML
root = true

[providers.appcfg]
type = "azure-ac"
endpoint = { secret = "FNOX_TEST_UNSET_ENDPOINT" }

[secrets]
API_URL = { provider = "appcfg", value = "API_URL", if_missing = "$mode" }
TOML

		run "$FNOX_BIN" exec -- echo "should not run"
		assert_failure
		assert_output --partial "FNOX_TEST_UNSET_ENDPOINT"
		refute_output --partial "should not run"
	done
}

@test "fnox export fails when a provider's own settings don't resolve with if_missing=ignore" {
	cat >fnox.toml <<'TOML'
root = true

[providers.appcfg]
type = "azure-ac"
endpoint = { secret = "FNOX_TEST_UNSET_ENDPOINT" }

[secrets]
API_URL = { provider = "appcfg", value = "API_URL", if_missing = "ignore" }
TOML

	run "$FNOX_BIN" export
	assert_failure
	assert_output --partial "FNOX_TEST_UNSET_ENDPOINT"
}
