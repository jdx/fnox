#!/usr/bin/env bats
#
# gopass Provider Tests
#
# Uses a stub `gopass` executable so no real store or GPG key is required.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	STUB_DIR="$BATS_TEST_TMPDIR/stub"
	STORE="$BATS_TEST_TMPDIR/store"
	mkdir -p "$STUB_DIR" "$STORE"
	cat >"$STUB_DIR/gopass" <<'STUB'
#!/usr/bin/env bash
store="$GOPASS_STUB_STORE"
case "$1" in
cat)
	[ -f "$store/$2" ] || { echo "Error: Entry is not in the password store" >&2; exit 1; }
	cat "$store/$2"
	;;
insert)
	[ "$2" = "-f" ] || exit 2
	mkdir -p "$(dirname "$store/$3")"
	cat >"$store/$3"
	;;
ls)
	find "$store" -type f
	;;
*) exit 2 ;;
esac
STUB
	chmod +x "$STUB_DIR/gopass"
	export GOPASS_STUB_STORE="$STORE"
	export PATH="$STUB_DIR:$PATH"
}

teardown() {
	_common_teardown
}

@test "gopass provider reads a secret through the mount" {
	mkdir -p "$STORE/company/apps"
	printf 's3cret\n' >"$STORE/company/apps/db"

	cat >fnox.toml <<'TOML'
[providers.gopass]
type = "gopass"
mount = "company"

[secrets]
DB = { provider = "gopass", value = "apps/db" }
TOML

	run "$FNOX_BIN" get DB
	assert_success
	assert_output "s3cret"
}

@test "gopass provider set stores the secret" {
	cat >fnox.toml <<'TOML'
[providers.gopass]
type = "gopass"
TOML

	run "$FNOX_BIN" set TOKEN "abc123" --provider gopass
	assert_success
	run "$FNOX_BIN" get TOKEN
	assert_success
	assert_output "abc123"
}

@test "gopass provider reports a missing secret" {
	cat >fnox.toml <<'TOML'
[providers.gopass]
type = "gopass"

[secrets]
MISSING = { provider = "gopass", value = "nope", if_missing = "error" }
TOML

	run "$FNOX_BIN" get MISSING
	assert_failure
}

@test "gopass provider preserves whitespace in secret values" {
	cat >fnox.toml <<'TOML'
[providers.gopass]
type = "gopass"
TOML

	run "$FNOX_BIN" set PADDED "  secret  " --provider gopass
	assert_success
	[ "$(cat "$STORE/PADDED")" = "  secret  " ]
	run "$FNOX_BIN" get PADDED
	assert_success
	assert_output "  secret  "
}
