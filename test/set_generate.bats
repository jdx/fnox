#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
	cat >fnox.toml <<'EOT'
root = true

[providers.plain]
type = "plain"

[secrets]
EOT
}

teardown() {
	_common_teardown
}

@test "set --generate stores a 32-char value and does not print it" {
	run "$FNOX_BIN" set TOKEN --generate --provider plain
	assert_success
	assert_output --partial "generated a random password value"
	run "$FNOX_BIN" get TOKEN
	assert_success
	[[ ${#output} -eq 32 ]]
	[[ $output =~ ^[A-Za-z0-9_-]+$ ]]
}

@test "set --generate --show prints the stored value" {
	run "$FNOX_BIN" set TOKEN --generate --generate-type hex --length 20 --show --provider plain
	assert_success
	shown=$(printf '%s\n' "$output" | tail -n1)
	run "$FNOX_BIN" get TOKEN
	assert_success
	assert_output "$shown"
	[[ ${#shown} -eq 20 ]]
}

@test "set --generate refuses to overwrite without --force" {
	run "$FNOX_BIN" set TOKEN old --provider plain
	assert_success
	run "$FNOX_BIN" set TOKEN --generate --provider plain
	assert_failure
	assert_output --partial "--force"
	run "$FNOX_BIN" get TOKEN
	assert_output "old"
	run "$FNOX_BIN" set TOKEN --generate --force --provider plain
	assert_success
	run "$FNOX_BIN" get TOKEN
	refute_output "old"
}

@test "set --generate rejects length 0" {
	run "$FNOX_BIN" set TOKEN --generate --length 0 --provider plain
	assert_failure
}

@test "set --generate --dry-run does not print the value" {
	run "$FNOX_BIN" set TOKEN --generate --dry-run --provider plain
	assert_success
	refute_output --partial "value:"
}

@test "set --generate refuses when fnox.local.toml shadows the target entry" {
	run "$FNOX_BIN" set TOKEN old --provider plain
	assert_success
	cat >fnox.local.toml <<'EOT'
[secrets]
TOKEN = { provider = "plain", value = "local" }
EOT
	run "$FNOX_BIN" set TOKEN --generate --provider plain
	assert_failure
	assert_output --partial "--force"
}

@test "set --generate --dry-run --show prints the generated value" {
	run "$FNOX_BIN" set TOKEN --generate --dry-run --show --length 60 --provider plain
	assert_success
	assert_output --regexp 'generated: [A-Za-z0-9_-]{60}'
}

@test "set --generate refuses to replace a provider reference without a value" {
	cat >fnox.toml <<'EOT'
root = true

[providers.plain]
type = "plain"

[secrets]
REF = { provider = "plain" }
EOT
	run "$FNOX_BIN" set REF --generate --provider plain
	assert_failure
	assert_output --partial "--force"
}
