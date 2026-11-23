#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup

	export FNOX_NO_DAEMON=1
	export FNOX_CONFIG_DIR="$HOME/.config/fnox"
	mkdir -p "$FNOX_CONFIG_DIR"

	age-keygen -o "$HOME/key.txt" 2>/dev/null
	FNOX_AGE_KEY="$(grep 'AGE-SECRET-KEY' "$HOME/key.txt")"
	export FNOX_AGE_KEY
	PUBLIC_KEY="$(grep 'public key:' "$HOME/key.txt" | cut -d: -f2- | xargs)"

	mkdir project
	cd project || exit 1
	cat >fnox.toml <<TOML
root = true
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$PUBLIC_KEY"]
TOML
}

teardown() {
	_common_teardown
}

@test "set --source keeps ciphertext in its own file" {
	run fnox set API_KEY hunter2 --source secrets/API_KEY.age
	assert_success

	run grep -c 'source = "secrets/API_KEY.age"' fnox.toml
	assert_output 1
	run grep -c 'value' fnox.toml
	assert_output 0
	assert [ -s secrets/API_KEY.age ]

	run fnox get API_KEY
	assert_success
	assert_output hunter2
}

@test "set updates the source file of an existing entry" {
	fnox set API_KEY one --source secrets/API_KEY.age
	before="$(cat secrets/API_KEY.age)"
	fnox set API_KEY two

	run grep -c 'source = "secrets/API_KEY.age"' fnox.toml
	assert_output 1
	assert [ "$(cat secrets/API_KEY.age)" != "$before" ]
	run fnox get API_KEY
	assert_output two
}

@test "reencrypt writes back to the source file" {
	fnox set API_KEY hunter2 --source secrets/API_KEY.age
	before="$(cat secrets/API_KEY.age)"
	run fnox reencrypt --force
	assert_success

	assert [ "$(cat secrets/API_KEY.age)" != "$before" ]
	run grep -c 'value' fnox.toml
	assert_output 0
	run fnox get API_KEY
	assert_output hunter2
}

@test "source and value together are refused" {
	cat >>fnox.toml <<'TOML'

[secrets]
BAD = { provider = "age", value = "x", source = "secrets/BAD.age" }
TOML
	run fnox list
	assert_failure
	assert_output --partial "sets both"
}

@test "source cannot leave the config directory" {
	cat >>fnox.toml <<'TOML'

[secrets]
BAD = { provider = "age", source = "../BAD.age" }
TOML
	run fnox list
	assert_failure
	assert_output --partial "relative path inside the config directory"
}

@test "set --source needs an encryption provider" {
	cat >>fnox.toml <<'TOML'

[providers.plain]
type = "plain"
TOML
	run fnox set PLAIN_KEY x -p plain --source secrets/P.age
	assert_failure
	assert [ ! -e secrets/P.age ]
}
