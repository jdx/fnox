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

@test "provider changes keep the config loadable" {
	fnox set API_KEY hunter2 --source secrets/API_KEY.age
	run fnox provider add extra plain
	assert_success
	run grep -c 'value' fnox.toml
	assert_output 0
	run fnox get API_KEY
	assert_success
	assert_output hunter2
}

@test "edit leaves source secrets out of the config and updates the file" {
	fnox set API_KEY hunter2 --source secrets/API_KEY.age
	before="$(cat secrets/API_KEY.age)"
	cp fnox.toml before.toml

	EDITOR=true run fnox edit
	assert_success
	run diff fnox.toml before.toml
	assert_success
	assert [ "$(cat secrets/API_KEY.age)" = "$before" ]

	cat >"$HOME/editor.sh" <<'SH'
#!/bin/sh
sed -i 's/hunter2/changed/' "$1"
SH
	chmod +x "$HOME/editor.sh"
	EDITOR="$HOME/editor.sh" run fnox edit
	assert_success
	run grep -c 'value' fnox.toml
	assert_output 0
	run fnox get API_KEY
	assert_output changed
}

@test "edit refuses to change a secret's source path" {
	fnox set API_KEY hunter2 --source secrets/API_KEY.age
	before="$(cat secrets/API_KEY.age)"
	cat >"$HOME/editor.sh" <<'SH'
#!/bin/sh
sed -i 's#secrets/API_KEY.age#secrets/OTHER.age#; s/hunter2/changed/' "$1"
SH
	chmod +x "$HOME/editor.sh"
	EDITOR="$HOME/editor.sh" run fnox edit
	assert_failure
	assert_output --partial "Cannot change \`source\`"
	assert [ "$(cat secrets/API_KEY.age)" = "$before" ]
	assert [ ! -e secrets/OTHER.age ]
}

@test "edit refuses to add a source to an inline secret" {
	fnox set API_KEY hunter2 --provider age
	cp fnox.toml before.toml
	cat >"$HOME/editor.sh" <<'SH'
#!/bin/sh
sed -i 's#^API_KEY= {#API_KEY= { source = "secrets/API_KEY.age",#' "$1"
SH
	chmod +x "$HOME/editor.sh"
	EDITOR="$HOME/editor.sh" run fnox edit
	assert_failure
	run diff fnox.toml before.toml
	assert_success
}

@test "a profile secret cannot share the source file of a root secret" {
	fnox set A one --source secrets/shared.age
	cat >>fnox.toml <<'EOF2'

[profiles.dev.secrets.B]
source = "secrets/shared.age"
EOF2
	run fnox get A
	assert_failure
	assert_output --partial "same \`source\` file"
}

@test "two secrets cannot share a source file" {
	fnox set A one --source secrets/shared.age
	run fnox set B two --source secrets/shared.age
	assert_failure
	assert_output --partial "already exists"
	run fnox get A
	assert_output one
}

@test "an existing file is not overwritten by a new source" {
	mkdir secrets
	echo keep >secrets/mine.age
	run fnox set A one --source secrets/mine.age
	assert_failure
	assert [ "$(cat secrets/mine.age)" = keep ]
	run grep -c 'secrets/mine.age' fnox.toml
	assert_output 0
}

@test "the config file cannot be its own source" {
	run fnox set A one --source fnox.toml
	assert_failure
	assert_output --partial "is the config file"
}

@test "a linked directory cannot lead out of the config directory" {
	mkdir "$HOME/outside"
	ln -s "$HOME/outside" linked
	run fnox set A one --source linked/A.age
	assert_failure
	assert [ ! -e "$HOME/outside/A.age" ]
}

@test "a child config does not share the parent's source file" {
	fnox set A one --source secrets/A.age
	mkdir child
	run bash -c "cd child && fnox set A two"
	assert_success
	run grep -c 'source' child/fnox.toml
	assert_output 0
	run bash -c "cd child && fnox get A"
	assert_output two
	run fnox get A
	assert_output one
}
