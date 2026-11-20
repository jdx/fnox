#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

write_config() {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
# first
FIRST = { provider = "plain", value = "one" }
# keep this comment
OLD_KEY = { provider = "plain", value = "secret-value", description = "my key" }
LAST = { provider = "plain", value = "three" }

[profiles.staging.secrets]
STAGE_OLD = { provider = "plain", value = "stage" }
TOML
}

@test "fnox rename keeps value, fields, position and comments" {
	write_config
	assert_fnox_success rename OLD_KEY NEW_KEY
	assert_output --partial "Renamed secret"

	run grep -n "OLD_KEY" fnox.toml
	assert_failure
	run cat fnox.toml
	assert_output --partial '# keep this comment'
	assert_output --partial 'NEW_KEY = { provider = "plain", value = "secret-value", description = "my key" }'

	# order preserved: FIRST, NEW_KEY, LAST
	first=$(grep -n '^FIRST' fnox.toml | cut -d: -f1)
	renamed=$(grep -n '^NEW_KEY' fnox.toml | cut -d: -f1)
	last=$(grep -n '^LAST' fnox.toml | cut -d: -f1)
	[ "$first" -lt "$renamed" ]
	[ "$renamed" -lt "$last" ]

	assert_fnox_success get NEW_KEY
	assert_output "secret-value"
}

@test "fnox mv is an alias for rename" {
	write_config
	assert_fnox_success mv OLD_KEY NEW_KEY
	assert_fnox_success get NEW_KEY
}

@test "fnox rename --dry-run does not change the file" {
	write_config
	cp fnox.toml fnox.toml.orig
	assert_fnox_success rename OLD_KEY NEW_KEY --dry-run
	assert_output --partial "Would rename secret"
	diff fnox.toml fnox.toml.orig
}

@test "fnox rename refuses an existing target name" {
	write_config
	cp fnox.toml fnox.toml.orig
	assert_fnox_failure rename OLD_KEY LAST
	assert_output --partial "already exists"
	diff fnox.toml fnox.toml.orig
}

@test "fnox rename fails for a missing secret" {
	write_config
	assert_fnox_failure rename MISSING NEW_KEY
	assert_output --partial "not found"
}

@test "fnox rename fails when names are identical" {
	write_config
	assert_fnox_failure rename OLD_KEY OLD_KEY
}

@test "fnox -P renames within a profile table" {
	write_config
	assert_fnox_success -P staging rename STAGE_OLD STAGE_NEW
	run grep -c '^STAGE_NEW' fnox.toml
	assert_output "1"
	run grep -c '^OLD_KEY' fnox.toml
	assert_output "1"
}

@test "fnox rename rejects an invalid new name and leaves the file unchanged" {
	write_config
	cp fnox.toml fnox.toml.orig
	assert_fnox_failure rename OLD_KEY 'BAD-KEY'
	assert_fnox_failure rename OLD_KEY 'BAD-KEY' --dry-run
	diff fnox.toml fnox.toml.orig
}

@test "fnox rename works with an inline secrets table" {
	cat >fnox.toml <<'TOML'
root = true
secrets = { OLD_KEY = { provider = "plain", value = "v" }, OTHER = { provider = "plain", value = "o" } }

[providers.plain]
type = "plain"
TOML
	assert_fnox_success rename OLD_KEY NEW_KEY
	assert_fnox_success get NEW_KEY
	assert_output "v"
	assert_fnox_success get OTHER
}

@test "fnox rename in a profile file's other profile edits the right table" {
	cat >fnox.staging.toml <<'TOML'
[providers.plain]
type = "plain"

[secrets]
OLD = { provider = "plain", value = "staging" }

[profiles.dev.secrets]
OLD = { provider = "plain", value = "dev" }
TOML
	assert_fnox_success -c fnox.staging.toml -P dev rename OLD NEW
	run grep -c '^NEW' fnox.staging.toml
	assert_output "1"
	# the staging profile's own OLD is untouched
	run grep -c "^OLD" fnox.staging.toml
	assert_output "1"
	run grep -A1 "^\[secrets\]" fnox.staging.toml
	assert_output --partial "OLD ="
}

@test "fnox rename keeps the spelling of untouched quoted keys" {
	cat >fnox.toml <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
'QUOTED' = { provider = "plain", value = "q" }
OLD_KEY = { provider = "plain", value = "v" }
TOML
	assert_fnox_success rename OLD_KEY NEW_KEY
	run grep -c "^'QUOTED'" fnox.toml
	assert_output "1"
}

@test "fnox rename works with -c fnox.default.toml" {
	cat >fnox.default.toml <<'TOML'
[providers.plain]
type = "plain"

[secrets]
OLD_KEY = { provider = "plain", value = "v" }
TOML
	assert_fnox_success -c fnox.default.toml rename OLD_KEY NEW_KEY
	run grep -c "^NEW_KEY" fnox.default.toml
	assert_output "1"
}
