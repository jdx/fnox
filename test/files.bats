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

	cat >"$FNOX_CONFIG_DIR/config.toml" <<TOML
default_provider = "age"

[providers.age]
type = "age"
recipients = ["$PUBLIC_KEY"]
TOML

	# Stop discovery here so the repository's own fnox.toml is not layered over the global config
	mkdir project
	cd project || exit 1
	echo 'root = true' >fnox.toml
}

teardown() {
	_common_teardown
}

@test "files: set stores a file under its path and get prints it verbatim" {
	printf 'apiVersion: v1\ntoken: abc123' >"$HOME/source"

	run fnox set --file ~/.kube/config --from-file "$HOME/source"
	assert_success

	run grep -F '"~/.kube/config"' "$FNOX_CONFIG_DIR/config.toml"
	assert_success
	run grep -F 'abc123' "$FNOX_CONFIG_DIR/config.toml"
	assert_failure

	# No trailing newline is added
	run fnox get --file "$HOME/.kube/config"
	assert_success
	[ "$output" = $'apiVersion: v1\ntoken: abc123' ]
	[ "$(fnox get --file ~/.kube/config | wc -c)" -eq 28 ]
}

@test "files: set without --from-file reads the file at the path" {
	mkdir -p "$HOME/.aws"
	printf '[default]\naws_access_key_id = AKIA\n' >"$HOME/.aws/credentials"

	run fnox set --file ~/.aws/credentials
	assert_success

	rm "$HOME/.aws/credentials"
	run fnox files write
	assert_success
	run cat "$HOME/.aws/credentials"
	assert_output --partial "AKIA"
}

@test "files: write creates the file with mode 0600 and is idempotent" {
	printf 'secret\n' >"$HOME/source"
	fnox set --file ~/.npmrc --from-file "$HOME/source"

	run fnox files write
	assert_success
	assert_output --partial "Wrote ~/.npmrc"
	[ "$(stat -c %a "$HOME/.npmrc" 2>/dev/null || stat -f %Lp "$HOME/.npmrc")" = "600" ]
	[ "$(cat "$HOME/.npmrc")" = "secret" ]

	chmod 644 "$HOME/.npmrc"
	run fnox files write
	assert_success
	assert_output --partial "up to date"
	[ "$(stat -c %a "$HOME/.npmrc" 2>/dev/null || stat -f %Lp "$HOME/.npmrc")" = "600" ]
}

@test "files: write replaces a symlink instead of writing through it" {
	printf 'secret\n' >"$HOME/source"
	fnox set --file ~/.npmrc --from-file "$HOME/source"
	printf 'keep me\n' >"$HOME/elsewhere"
	ln -s "$HOME/elsewhere" "$HOME/.npmrc"

	run fnox files write
	assert_success
	[ ! -L "$HOME/.npmrc" ]
	[ "$(cat "$HOME/elsewhere")" = "keep me" ]
	[ "$(cat "$HOME/.npmrc")" = "secret" ]
}

@test "files: write --dry-run changes nothing" {
	printf 'secret\n' >"$HOME/source"
	fnox set --file ~/.npmrc --from-file "$HOME/source"

	run fnox files write --dry-run
	assert_success
	assert_output --partial "Would write ~/.npmrc"
	[ ! -e "$HOME/.npmrc" ]
}

@test "files: write with a path limits it to that file" {
	printf 'one\n' >"$HOME/one"
	printf 'two\n' >"$HOME/two"
	fnox set --file ~/.one --from-file "$HOME/one"
	fnox set --file ~/.two --from-file "$HOME/two"

	run fnox files write ~/.two
	assert_success
	[ ! -e "$HOME/.one" ]
	[ "$(cat "$HOME/.two")" = "two" ]

	run fnox files write ~/.missing
	assert_failure
	assert_output --partial "No file"
}

@test "files: a file never reaches the environment" {
	printf 'UNIQUE_FILE_MARKER\n' >"$HOME/source"
	fnox set --file ~/.npmrc --from-file "$HOME/source"

	run fnox exec -- env
	assert_success
	refute_output --partial "UNIQUE_FILE_MARKER"
	run fnox export
	refute_output --partial "UNIQUE_FILE_MARKER"
}

@test "files: edit changes the stored content" {
	printf 'token: abc\n' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source"

	EDITOR="sed -i.bak s/abc/xyz/" run fnox edit --file ~/.kube/config
	assert_success

	run fnox get --file ~/.kube/config
	assert_output "token: xyz"
}

@test "files: edit leaves the file alone when the editor changes nothing" {
	printf 'token: abc' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source"
	before="$(cat "$FNOX_CONFIG_DIR/config.toml")"

	EDITOR="true" run fnox edit --file ~/.kube/config
	assert_success
	assert_output --partial "unchanged"
	[ "$before" = "$(cat "$FNOX_CONFIG_DIR/config.toml")" ]
}

@test "files: source keeps the stored content out of the config" {
	printf 'token: abc\n' >"$HOME/source"
	run fnox set --file ~/.kube/config --from-file "$HOME/source" --source files/kube.age
	assert_success

	[ -s "$FNOX_CONFIG_DIR/files/kube.age" ]
	run grep -F 'source = "files/kube.age"' "$FNOX_CONFIG_DIR/config.toml"
	assert_success
	run grep -F 'value' "$FNOX_CONFIG_DIR/config.toml"
	assert_failure

	run fnox get --file ~/.kube/config
	assert_output "token: abc"

	# A later set keeps using the source file
	printf 'token: def\n' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source"
	run fnox get --file ~/.kube/config
	assert_output "token: def"
	run grep -F 'value' "$FNOX_CONFIG_DIR/config.toml"
	assert_failure
}

@test "files: a source outside the config directory is rejected" {
	printf 'x\n' >"$HOME/source"
	run fnox set --file ~/.npmrc --from-file "$HOME/source" --source ../escape.age
	assert_failure
	assert_output --partial "relative path inside the config directory"
}

@test "files: profiles override the default and are selected with -P" {
	printf 'base\n' >"$HOME/base"
	printf 'work\n' >"$HOME/work"
	fnox set --file ~/.npmrc --from-file "$HOME/base"
	fnox -P work set --file ~/.npmrc --from-file "$HOME/work"

	run fnox get --file ~/.npmrc
	assert_output "base"
	run fnox -P work get --file ~/.npmrc
	assert_output "work"
	run grep -F '[profiles.work.files]' "$FNOX_CONFIG_DIR/config.toml"
	assert_success
}

@test "files: list shows the path, profile and provider without decrypting" {
	printf 'x\n' >"$HOME/source"
	fnox set --file ~/.npmrc --from-file "$HOME/source"

	FNOX_AGE_KEY="" run fnox files list
	assert_success
	assert_output --partial ".npmrc"
	assert_output --partial "age"
}

@test "files: remove deletes the entry but not the file" {
	printf 'x\n' >"$HOME/source"
	fnox set --file ~/.npmrc --from-file "$HOME/source"
	fnox files write

	run fnox remove --file ~/.npmrc
	assert_success
	run fnox get --file ~/.npmrc
	assert_failure
	[ -f "$HOME/.npmrc" ]
}

@test "files: a project config cannot declare files" {
	cat >fnox.toml <<'TOML'
root = true

[files]
"~/.ssh/authorized_keys" = { provider = "age", value = "x" }
TOML

	run fnox files list
	assert_failure
	assert_output --partial "only allowed in the global config"
}

@test "files: a project profile cannot declare files either" {
	cat >fnox.toml <<'TOML'
root = true

[profiles.evil.files]
"~/.bashrc" = { provider = "age", value = "x" }
TOML

	run fnox -P evil files write
	assert_failure
	assert_output --partial "only allowed in the global config"
	[ ! -e "$HOME/.bashrc" ]
}

@test "files: a relative key is rejected" {
	cat >>"$FNOX_CONFIG_DIR/config.toml" <<'TOML'

[files]
".kube/config" = { provider = "age", value = "x" }
TOML

	run fnox files list
	assert_failure
	assert_output --partial "must be absolute"
}

@test "files: tilde and absolute spellings name the same file" {
	printf 'one\n' >"$HOME/one"
	printf 'two\n' >"$HOME/two"
	fnox set --file ~/.npmrc --from-file "$HOME/one"
	fnox set --file "$HOME/.npmrc" --from-file "$HOME/two"

	run grep -c '\.npmrc' "$FNOX_CONFIG_DIR/config.toml"
	assert_output "1"
	run fnox get --file ~/.npmrc
	assert_output "two"
}

@test "files: get of an unknown file suggests the known ones" {
	printf 'x\n' >"$HOME/source"
	fnox set --file ~/.npmrc --from-file "$HOME/source"

	run fnox get --file ~/.npmrcc
	assert_failure
	assert_output --partial "No file"
}

@test "files: a provider that cannot store files is refused" {
	cat >>"$FNOX_CONFIG_DIR/config.toml" <<'TOML'

[providers.plain]
type = "plain"
TOML
	printf 'x\n' >"$HOME/source"

	run fnox set --file ~/.npmrc --from-file "$HOME/source" --provider plain
	assert_failure
	assert_output --partial "can neither encrypt nor store files"
	[ ! -e "$HOME/.npmrc" ]
}

@test "files: set --file rejects flags that only apply to secrets" {
	run fnox set --file ~/.npmrc --generate
	assert_failure
	assert_output --partial "does not apply to --file"
}

@test "files: reencrypt moves files to new recipients" {
	age-keygen -o "$HOME/key2.txt" 2>/dev/null
	new_public="$(grep 'public key:' "$HOME/key2.txt" | cut -d: -f2- | xargs)"
	new_secret="$(grep 'AGE-SECRET-KEY' "$HOME/key2.txt")"

	printf 'token: abc\n' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source"
	printf 'inline\n' >"$HOME/source2"
	fnox set --file ~/.npmrc --from-file "$HOME/source2" --source files/npmrc.age

	sed -i.bak "s|recipients = .*|recipients = [\"$new_public\"]|" "$FNOX_CONFIG_DIR/config.toml"
	run fnox reencrypt --force
	assert_success
	assert_output --partial "Re-encrypted 2 files"

	FNOX_AGE_KEY="$new_secret" run fnox get --file ~/.kube/config
	assert_success
	assert_output "token: abc"
	FNOX_AGE_KEY="$new_secret" run fnox get --file ~/.npmrc
	assert_success
	assert_output "inline"
}
