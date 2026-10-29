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

# Errors are wrapped to the terminal width, which can split a message across
# lines, so match it with the lines joined
assert_error() {
	local flat
	flat="$(printf '%s' "$output" | tr -s ' \n│' ' ')"
	[[ $flat == *"$1"* ]] || {
		echo "error does not contain '$1':"
		echo "$output"
		return 1
	}
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

@test "files: a global config that is a symlink can declare files" {
	mkdir -p "$HOME/dotfiles"
	mv "$FNOX_CONFIG_DIR/config.toml" "$HOME/dotfiles/config.toml"
	ln -s "$HOME/dotfiles/config.toml" "$FNOX_CONFIG_DIR/config.toml"
	printf 'token\n' >"$HOME/source"

	run fnox set --file ~/.npmrc --from-file "$HOME/source"
	assert_success
	run fnox get --file ~/.npmrc
	assert_success
	assert_output "token"

	# The entry went into the linked file and the link is kept
	[ -L "$FNOX_CONFIG_DIR/config.toml" ]
	run grep -F '"~/.npmrc"' "$HOME/dotfiles/config.toml"
	assert_success
}

@test "files: a source that is a symlink is read and written through" {
	printf 'token: abc\n' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source" --source files/kube.age
	mkdir -p "$HOME/dotfiles"
	mv "$FNOX_CONFIG_DIR/files/kube.age" "$HOME/dotfiles/kube.age"
	ln -s "$HOME/dotfiles/kube.age" "$FNOX_CONFIG_DIR/files/kube.age"

	run fnox get --file ~/.kube/config
	assert_success
	assert_output "token: abc"

	printf 'token: def\n' >"$HOME/source"
	run fnox set --file ~/.kube/config --from-file "$HOME/source"
	assert_success
	[ -L "$FNOX_CONFIG_DIR/files/kube.age" ]
	run fnox get --file ~/.kube/config
	assert_output "token: def"
}

@test "files: reencrypt writes through a linked source" {
	age-keygen -o "$HOME/key2.txt" 2>/dev/null
	new_public="$(grep 'public key:' "$HOME/key2.txt" | cut -d: -f2- | xargs)"
	new_secret="$(grep 'AGE-SECRET-KEY' "$HOME/key2.txt")"

	printf 'token: abc\n' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source" --source files/kube.age
	mkdir -p "$HOME/dotfiles"
	mv "$FNOX_CONFIG_DIR/files/kube.age" "$HOME/dotfiles/kube.age"
	ln -s "$HOME/dotfiles/kube.age" "$FNOX_CONFIG_DIR/files/kube.age"

	sed -i.bak "s|recipients = .*|recipients = [\"$new_public\"]|" "$FNOX_CONFIG_DIR/config.toml"
	run fnox reencrypt --force
	assert_success

	[ -L "$FNOX_CONFIG_DIR/files/kube.age" ]
	FNOX_AGE_KEY="$new_secret" run fnox get --file ~/.kube/config
	assert_success
	assert_output "token: abc"
}

@test "files: set refuses a linked source whose target is missing" {
	printf 'token: abc\n' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source" --source files/kube.age
	rm "$FNOX_CONFIG_DIR/files/kube.age"
	ln -s "$HOME/dotfiles/missing.age" "$FNOX_CONFIG_DIR/files/kube.age"

	run fnox set --file ~/.kube/config --from-file "$HOME/source"
	assert_failure
	assert_error "cannot be resolved"
	[ -L "$FNOX_CONFIG_DIR/files/kube.age" ]
}

@test "files: set refuses a linked source that is the config file" {
	printf 'token: abc\n' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source" --source files/kube.age
	ln -sf "$FNOX_CONFIG_DIR/config.toml" "$FNOX_CONFIG_DIR/files/kube.age"
	cp "$FNOX_CONFIG_DIR/config.toml" "$HOME/config.before"

	run fnox set --file ~/.kube/config --from-file "$HOME/source"
	assert_failure
	assert_error "is the config file"
	cmp "$FNOX_CONFIG_DIR/config.toml" "$HOME/config.before"
}

@test "files: set refuses a linked source that stores another file" {
	printf 'kube\n' >"$HOME/kube"
	printf 'npm\n' >"$HOME/npm"
	fnox set --file ~/.kube/config --from-file "$HOME/kube" --source files/kube.age
	fnox set --file ~/.npmrc --from-file "$HOME/npm" --source files/npmrc.age
	ln -sf "$FNOX_CONFIG_DIR/files/kube.age" "$FNOX_CONFIG_DIR/files/npmrc.age"

	run fnox set --file ~/.npmrc --from-file "$HOME/npm"
	assert_failure
	assert_error "already stores ~/.kube/config"
	run fnox get --file ~/.kube/config
	assert_output "kube"
}

@test "files: reencrypt refuses linked sources that store one file twice" {
	printf 'kube\n' >"$HOME/kube"
	fnox set --file ~/.kube/config --from-file "$HOME/kube" --source files/kube.age
	fnox set --file ~/.npmrc --from-file "$HOME/kube" --source files/npmrc.age
	ln -sf "$FNOX_CONFIG_DIR/files/kube.age" "$FNOX_CONFIG_DIR/files/npmrc.age"
	cp "$FNOX_CONFIG_DIR/files/kube.age" "$HOME/kube.before"

	run fnox reencrypt --force
	assert_failure
	assert_error "already stores"
	cmp "$FNOX_CONFIG_DIR/files/kube.age" "$HOME/kube.before"
}

@test "files: a project config linked to the config directory cannot declare files" {
	cat >"$FNOX_CONFIG_DIR/project.toml" <<'TOML'
root = true

[files]
"~/.bashrc" = { provider = "age", value = "x" }
TOML
	rm fnox.toml
	ln -s "$FNOX_CONFIG_DIR/project.toml" fnox.toml

	run fnox files list
	assert_failure
	assert_output --partial "allowed"
}

@test "files: a source outside the config directory is rejected" {
	printf 'x\n' >"$HOME/source"
	run fnox set --file ~/.npmrc --from-file "$HOME/source" --source ../escape.age
	assert_failure
	assert_output --partial "relative"
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
	assert_output --partial "allowed"
}

@test "files: a project profile cannot declare files either" {
	cat >fnox.toml <<'TOML'
root = true

[profiles.evil.files]
"~/.bashrc" = { provider = "age", value = "x" }
TOML

	run fnox -P evil files write
	assert_failure
	assert_output --partial "allowed"
	[ ! -e "$HOME/.bashrc" ]
}

@test "files: a relative key is rejected" {
	cat >>"$FNOX_CONFIG_DIR/config.toml" <<'TOML'

[files]
".kube/config" = { provider = "age", value = "x" }
TOML

	run fnox files list
	assert_failure
	assert_output --partial "absolute"
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
	assert_output --partial "neither"
	[ ! -e "$HOME/.npmrc" ]
}

@test "files: set --file rejects flags that only apply to secrets" {
	run fnox set --file ~/.npmrc --generate
	assert_failure
	assert_output --partial "apply"
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

@test "files: a project cannot replace the provider that reads a global file" {
	printf 'secret-token' >"$HOME/source"
	fnox set --file ~/.token --from-file "$HOME/source"

	# A project provider of the same name must not supply the file's content
	cat >fnox.toml <<'TOML'
root = true

[providers.age]
type = "plain"
TOML
	run fnox get --file ~/.token
	assert_success
	[ "$output" = "secret-token" ]
}

@test "files: a profile override keeps its own storage" {
	printf 'base' >"$HOME/base"
	printf 'work' >"$HOME/work"
	fnox set --file ~/.token --from-file "$HOME/base" --source files/token.age

	# The base's stored file is not the override's to overwrite
	run fnox -P work set --file ~/.token --from-file "$HOME/work" --source files/token.age
	assert_failure
	assert_output --partial "exists"

	run fnox -P work set --file ~/.token --from-file "$HOME/work"
	assert_success
	run fnox get --file ~/.token
	assert_output "base"
	run fnox -P work get --file ~/.token
	assert_output "work"
}

@test "files: a source cannot overwrite a config or another file's content" {
	printf 'x' >"$HOME/source"
	cp "$FNOX_CONFIG_DIR/config.toml" "$HOME/config.before"

	run fnox set --file ~/.token --from-file "$HOME/source" --source config.toml
	assert_failure
	assert_output --partial "exists"
	run diff "$FNOX_CONFIG_DIR/config.toml" "$HOME/config.before"
	assert_success
}

@test "files: set keeps entries when the files table is inline" {
	{
		echo 'files = { "~/.first" = { provider = "age", value = "ciphertext" } }'
		cat "$FNOX_CONFIG_DIR/config.toml"
	} >"$HOME/merged.toml"
	cp "$HOME/merged.toml" "$FNOX_CONFIG_DIR/config.toml"
	printf 'x' >"$HOME/source"
	run fnox set --file ~/.second --from-file "$HOME/source"
	assert_success
	run fnox files list
	assert_output --partial ".first"
	assert_output --partial ".second"
}

@test "files: remove deletes an entry declared in an import" {
	cat >"$FNOX_CONFIG_DIR/extra.toml" <<'TOML'
[files."~/.imported"]
provider = "age"
value = "ciphertext"
TOML
	echo 'import = ["extra.toml"]' | cat - "$FNOX_CONFIG_DIR/config.toml" >"$HOME/merged.toml"
	cp "$HOME/merged.toml" "$FNOX_CONFIG_DIR/config.toml"

	run fnox files list
	assert_output --partial ".imported"
	run fnox remove --file ~/.imported
	assert_success
	run fnox files list
	refute_output --partial ".imported"
}

@test "files: files of a fnox.<profile>.toml import belong to that profile" {
	cat >"$FNOX_CONFIG_DIR/fnox.work.toml" <<'TOML'
[files."~/.worky"]
provider = "age"
value = "ciphertext"
TOML
	echo 'import = ["fnox.work.toml"]' | cat - "$FNOX_CONFIG_DIR/config.toml" >"$HOME/merged.toml"
	cp "$HOME/merged.toml" "$FNOX_CONFIG_DIR/config.toml"

	run fnox files list
	refute_output --partial ".worky"
	run fnox -P work files list
	assert_output --partial ".worky"
}

@test "files: edit keeps a final newline the editor adds" {
	printf 'abc' >"$HOME/source"
	fnox set --file ~/.token --from-file "$HOME/source"

	printf '#!/bin/sh\nprintf "\\n" >>"$1"\n' >"$HOME/append-newline"
	chmod +x "$HOME/append-newline"

	EDITOR="$HOME/append-newline" run fnox edit --file ~/.token
	assert_success
	[ "$(fnox get --file ~/.token | wc -c)" -eq 4 ]
}

@test "files: a local file in the config directory keeps its files in the default profile" {
	cat >"$FNOX_CONFIG_DIR/fnox.local.toml" <<'TOML'
[files."~/.localfile"]
provider = "age"
value = "ciphertext"
TOML
	cd "$FNOX_CONFIG_DIR" || exit 1

	run fnox -P work files list
	assert_success
	assert_output --partial ".localfile"
	assert_output --partial "default"

	run fnox remove --file ~/.localfile
	assert_success
	run grep -F '.localfile' "$FNOX_CONFIG_DIR/fnox.local.toml"
	assert_failure
}

@test "files: declining the file prompt cancels reencrypt as a whole" {
	age-keygen -o "$HOME/key2.txt" 2>/dev/null
	new_public="$(grep 'public key:' "$HOME/key2.txt" | cut -d: -f2- | xargs)"

	printf 'token: abc\n' >"$HOME/source"
	fnox set --file ~/.kube/config --from-file "$HOME/source"
	fnox set SECRET_ONE secret-value

	sed -i.bak "s|recipients = .*|recipients = [\"$new_public\"]|" "$FNOX_CONFIG_DIR/config.toml"
	cp "$FNOX_CONFIG_DIR/config.toml" "$HOME/config.recipients"
	# Only one answer is given: a second prompt would read end of input and cancel too,
	# so the output must hold a single prompt
	run bash -c "printf 'n\n' | fnox reencrypt"
	assert_success
	assert_output --partial "cancelled"
	[ "$(grep -c 'Continue?' <<<"$output")" -eq 1 ]
	run diff "$FNOX_CONFIG_DIR/config.toml" "$HOME/config.recipients"
	assert_success
}
