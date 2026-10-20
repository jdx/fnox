#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
	_common_setup
}

@test "fnox export with if_missing=error fails on missing secret" {
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

	run "$FNOX_BIN" export
	assert_failure
}

@test "fnox export with if_missing=warn continues on missing secret" {
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

	run bash -c '"$1" export 2>/dev/null' _ "$FNOX_BIN"
	assert_success
	# Should output clean env format even though secret failed to resolve
	assert_output ""
}

@test "fnox export with default if_missing (warn) continues on missing secret" {
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

	run bash -c '"$1" export 2>/dev/null' _ "$FNOX_BIN"
	assert_success
	# Should output clean env format even though secret failed to resolve
	assert_output ""
}

@test "fnox export with if_missing=ignore silently continues on missing secret" {
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

	run bash -c '"$1" export 2>/dev/null' _ "$FNOX_BIN"
	assert_success
	# Should output clean env format even though secret failed to resolve
	assert_output ""
}

@test "fnox export KEY exports only named secrets, including env = false" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets.A_SECRET]
provider = "plain"
value = "alpha"

[secrets.B_SECRET]
provider = "plain"
value = "beta"

[secrets.HIDDEN_SECRET]
provider = "plain"
value = "hidden"
env = false
TOML

	run "$FNOX_BIN" export A_SECRET
	assert_success
	assert_output "A_SECRET=alpha"

	run "$FNOX_BIN" export --format json B_SECRET HIDDEN_SECRET
	assert_success
	assert_output --partial '"B_SECRET": "beta"'
	assert_output --partial '"HIDDEN_SECRET": "hidden"'
	refute_output --partial 'A_SECRET'
}

@test "fnox export KEY fails on an unknown key" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets.A_SECRET]
provider = "plain"
value = "alpha"
TOML

	run "$FNOX_BIN" export A_SECRET MISSING_SECRET
	assert_failure
	assert_output --partial "MISSING_SECRET"
}

@test "fnox export KEY resolves interpolated dependencies but exports only named keys" {
	cat >fnox.toml <<'TOML'
root = true

[secrets.DB_HOST]
default = "localhost"

[secrets.DATABASE_URL]
default = "postgres://${DB_HOST}/app"

[secrets.UNRELATED]
provider = "missing"
value = "x"
if_missing = "error"
TOML

	run "$FNOX_BIN" export --no-daemon DATABASE_URL
	assert_success
	assert_output "DATABASE_URL=postgres://localhost/app"
}
