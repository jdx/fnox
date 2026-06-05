#!/usr/bin/env bats
#
# Test that hook-env falls back to the COLUMNS environment variable for
# terminal width when stderr is not a TTY (the usual case in shell hooks)
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Eight secrets with 20-char names: the full key list is ~174 chars wide
	# root = true stops config recursion into parent directories (the test
	# temp dir lives inside the fnox repo, which has its own fnox.toml)
	cat >fnox.toml <<EOF
root = true

[providers.plain]
type = "plain"

[secrets.SECRET_AAAAAAAAAAAAA]
provider = "plain"
value = "value-a"

[secrets.SECRET_BBBBBBBBBBBBB]
provider = "plain"
value = "value-b"

[secrets.SECRET_CCCCCCCCCCCCC]
provider = "plain"
value = "value-c"

[secrets.SECRET_DDDDDDDDDDDDD]
provider = "plain"
value = "value-d"

[secrets.SECRET_EEEEEEEEEEEEE]
provider = "plain"
value = "value-e"

[secrets.SECRET_FFFFFFFFFFFFF]
provider = "plain"
value = "value-f"

[secrets.SECRET_GGGGGGGGGGGGG]
provider = "plain"
value = "value-g"

[secrets.SECRET_HHHHHHHHHHHHH]
provider = "plain"
value = "value-h"
EOF
}

teardown() {
	_common_teardown
}

@test "hook-env summary uses COLUMNS when stderr is not a tty (wide)" {
	# All 8 keys fit within 200 columns: no truncation
	# Capture only the stderr summary line; stdout carries the shell code
	run bash -c "COLUMNS=200 '$FNOX_BIN' hook-env -s bash 2>&1 >/dev/null"
	assert_success
	assert_output --partial "fnox: +8"
	assert_output --partial "SECRET_AAAAAAAAAAAAA"
	assert_output --partial "SECRET_HHHHHHHHHHHHH"
	refute_output --partial "..."
}

@test "hook-env summary uses COLUMNS when stderr is not a tty (narrow)" {
	# Only 2 of the 8 keys fit within 60 columns: the rest are truncated
	# (key order in the summary is not deterministic, so count keys instead)
	run bash -c "COLUMNS=60 '$FNOX_BIN' hook-env -s bash 2>&1 >/dev/null"
	assert_success
	assert_output --partial "fnox: +8"
	assert_output --partial "..."
	assert_equal "$(grep -o 'SECRET_' <<<"$output" | wc -l | tr -d ' ')" 2
}

@test "hook-env summary defaults to 80 columns without a tty or COLUMNS" {
	# At the default of 80 columns only 3 of the 8 keys fit
	run env -u COLUMNS bash -c "'$FNOX_BIN' hook-env -s bash 2>&1 >/dev/null"
	assert_success
	assert_output --partial "fnox: +8"
	assert_output --partial "..."
	assert_equal "$(grep -o 'SECRET_' <<<"$output" | wc -l | tr -d ' ')" 3
}
