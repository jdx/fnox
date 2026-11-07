#!/bin/bash
set -euo pipefail
script=$(cd "$(dirname "$0")/../.." && pwd)/scripts/enable-sudo-touch-id.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fixture=$work/pam
mkdir "$fixture"
fixture=$(cd "$fixture" && pwd -P)
printf 'auth include sudo_local\nauth sufficient pam_smartcard.so\n' >"$fixture/sudo"
printf '# Local "policy" \\ fixture\n#auth sufficient pam_tid.so\nauth optional pam_custom.so\n' >"$fixture/sudo_local.template"
run() { "$script" --pam-dir "$fixture" "$@"; }
expect_status() {
	expected=$1
	shift
	set +e
	"$@" >"$work/output" 2>&1
	actual=$?
	set -e
	[ "$actual" = "$expected" ] || {
		cat "$work/output"
		echo "Expected $expected, got $actual" >&2
		exit 1
	}
}
expect_status 1 run --check
expect_status 2 run --check --dry-run
description=$("$script" --describe --apply --pam-dir "$fixture")
[ "$description" = 'inspect or configure sudo Touch ID through an explicit PAM plan' ]
[ ! -e "$fixture/sudo_local" ]
help=$("$script" --help)
grep -q -- '--json' <<<"$help"
grep -q -- '--describe' <<<"$help"
run --dry-run >"$work/plan"
[ ! -e "$fixture/sudo_local" ]
grep -q "Planned destination: $fixture/sudo_local" "$work/plan"
grep -q 'pam_custom.so' "$work/plan"
expect_status 1 run --check --json
node - "$work/output" <<'NODE'
const fs = require('node:fs')
const result = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
if (result.ok !== true || result.exitCode !== 1 || result.data.configured !== false) {
	throw new Error('check JSON result is invalid')
}
NODE
run --dry-run --json >"$work/json-plan"
node - "$work/json-plan" "$fixture/sudo_local" <<'NODE'
const fs = require('node:fs')
const result = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
if (
	result.ok !== true ||
	result.exitCode !== 0 ||
	result.data.action !== 'create' ||
	result.data.destination !== process.argv[3] ||
	!result.data.proposedContents.endsWith('\n') ||
	!result.data.proposedContents.includes('# Local "policy" \\ fixture')
) {
	throw new Error('dry-run JSON result is invalid')
}
NODE
[ ! -e "$fixture/sudo_local" ]
expect_status 2 run --json --unsupported
node - "$work/output" <<'NODE'
const fs = require('node:fs')
const result = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
if (
	result.ok !== false ||
	result.exitCode !== 2 ||
	!result.error.includes('option') ||
	!result.error.includes('--unsupported') ||
	!result.error.includes('--help')
) {
	throw new Error('error JSON result is invalid')
}
NODE
run --apply --json >"$work/apply"
node - "$work/apply" "$fixture/sudo_local" <<'NODE'
const fs = require('node:fs')
const result = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
if (result.ok !== true || result.exitCode !== 0 || result.data.action !== 'created' || result.data.destination !== process.argv[3]) {
	throw new Error('apply JSON result is invalid')
}
NODE
run --check >/dev/null
[ "$(awk '$1=="auth" && $3=="pam_tid.so" {n++} END{print n}' "$fixture/sudo_local")" = 1 ]
grep -q 'pam_custom.so' "$fixture/sudo_local"
cp "$fixture/sudo_local" "$work/first"
run --apply >/dev/null
cmp "$fixture/sudo_local" "$work/first"
printf 'auth sufficient pam_tid.so\nauth sufficient pam_tid.so\n' >"$fixture/sudo_local"
cp "$fixture/sudo_local" "$work/rejected"
expect_status 2 run --apply
cmp "$fixture/sudo_local" "$work/rejected"
printf 'auth required pam_tid.so\n' >"$fixture/sudo_local"
cp "$fixture/sudo_local" "$work/rejected"
expect_status 2 run --apply
cmp "$fixture/sudo_local" "$work/rejected"
printf 'auth optional pam_custom.so\n' >"$fixture/sudo_local"
cp "$fixture/sudo_local" "$work/rejected"
expect_status 2 run --dry-run
cmp "$fixture/sudo_local" "$work/rejected"
expect_status 2 run --apply
cmp "$fixture/sudo_local" "$work/rejected"
printf 'auth sufficient pam_tid.so touch_timeout=30\n' >"$fixture/sudo_local"
run --check >/dev/null
cp "$fixture/sudo_local" "$work/with-options"
run --apply >/dev/null
cmp "$fixture/sudo_local" "$work/with-options"
rm "$fixture/sudo_local"
ln -s "$fixture/sudo_local.template" "$fixture/sudo_local"
expect_status 2 run --apply
[ -L "$fixture/sudo_local" ]
[ "$(readlink "$fixture/sudo_local")" = "$fixture/sudo_local.template" ]
rm "$fixture/sudo_local"
printf 'auth optional pam_custom.so\n' >"$fixture/sudo_local"
chmod 600 "$fixture/sudo_local"
cp "$fixture/sudo_local" "$work/before"
expect_status 2 run --apply
cmp "$work/before" "$fixture/sudo_local"
mode=$(stat -c '%a' "$fixture/sudo_local" 2>/dev/null || stat -f '%Lp' "$fixture/sudo_local")
[ "$mode" = 600 ]
if compgen -G "$fixture/sudo_local.fnox-backup.*" >/dev/null; then
	echo 'Unexpected backup created for rejected configuration.' >&2
	exit 1
fi
printf 'auth sufficient pam_smartcard.so\n' >"$fixture/sudo"
expect_status 2 run --apply
fresh_fixture=$work/no-template
mkdir "$fresh_fixture"
fresh_fixture=$(cd "$fresh_fixture" && pwd -P)
printf 'auth include sudo_local\n' >"$fresh_fixture/sudo"
"$script" --pam-dir "$fresh_fixture" --dry-run >"$work/no-template-plan"
[ ! -e "$fresh_fixture/sudo_local" ]
grep -q "Planned destination: $fresh_fixture/sudo_local" "$work/no-template-plan"
grep -q 'pam_tid.so' "$work/no-template-plan"
"$script" --pam-dir "$fresh_fixture" --apply >/dev/null
grep -q '^auth.*pam_tid[.]so' "$fresh_fixture/sudo_local"
unsafe_fixture=$work/unsafe-template
mkdir "$unsafe_fixture"
unsafe_fixture=$(cd "$unsafe_fixture" && pwd -P)
printf 'auth include sudo_local\n' >"$unsafe_fixture/sudo"
printf 'auth required pam_opendirectory.so\nauth requisite pam_deny.so\n' >"$unsafe_fixture/sudo_local.template"
expect_status 2 "$script" --pam-dir "$unsafe_fixture" --dry-run
[ ! -e "$unsafe_fixture/sudo_local" ]
expect_status 2 "$script" --pam-dir "$unsafe_fixture" --apply
[ ! -e "$unsafe_fixture/sudo_local" ]
sudo_order_fixture=$work/sudo-order
mkdir "$sudo_order_fixture"
sudo_order_fixture=$(cd "$sudo_order_fixture" && pwd -P)
printf 'auth required pam_opendirectory.so\nauth include sudo_local\n' >"$sudo_order_fixture/sudo"
printf '#auth sufficient pam_tid.so\n' >"$sudo_order_fixture/sudo_local.template"
expect_status 2 "$script" --pam-dir "$sudo_order_fixture" --apply
[ ! -e "$sudo_order_fixture/sudo_local" ]
expect_status 2 "$script" --pam-dir "$sudo_order_fixture" --check
printf 'auth include sudo_local\nauth required pam_opendirectory.so\n' >"$sudo_order_fixture/sudo"
printf 'auth sufficient pam_tid.so\nauth optional pam_custom.so # pam_tid.so\n' >"$sudo_order_fixture/sudo_local"
cp "$sudo_order_fixture/sudo_local" "$work/trailing-comment-policy"
"$script" --pam-dir "$sudo_order_fixture" --check >/dev/null
"$script" --pam-dir "$sudo_order_fixture" --dry-run >/dev/null
"$script" --pam-dir "$sudo_order_fixture" --apply >/dev/null
cmp "$work/trailing-comment-policy" "$sudo_order_fixture/sudo_local"
printf 'auth requisite pam_deny.so\nauth sufficient pam_tid.so\n' >"$sudo_order_fixture/sudo_local"
cp "$sudo_order_fixture/sudo_local" "$work/unsafe-local-order"
expect_status 2 "$script" --pam-dir "$sudo_order_fixture" --check
expect_status 2 "$script" --pam-dir "$sudo_order_fixture" --apply
cmp "$work/unsafe-local-order" "$sudo_order_fixture/sudo_local"
unsafe_mode_fixture=$work/unsafe-template-mode
mkdir "$unsafe_mode_fixture"
unsafe_mode_fixture=$(cd "$unsafe_mode_fixture" && pwd -P)
printf 'auth include sudo_local\n' >"$unsafe_mode_fixture/sudo"
printf '#auth sufficient pam_tid.so\n' >"$unsafe_mode_fixture/sudo_local.template"
chmod 666 "$unsafe_mode_fixture/sudo_local.template"
expect_status 2 "$script" --pam-dir "$unsafe_mode_fixture" --dry-run
[ ! -e "$unsafe_mode_fixture/sudo_local" ]
expect_status 2 "$script" --pam-dir "$unsafe_mode_fixture" --apply
[ ! -e "$unsafe_mode_fixture/sudo_local" ]
active_fixture=$work/active-template
mkdir "$active_fixture"
active_fixture=$(cd "$active_fixture" && pwd -P)
printf 'auth include sudo_local\n' >"$active_fixture/sudo"
printf 'auth sufficient pam_tid.so\n' >"$active_fixture/sudo_local.template"
chmod 600 "$active_fixture/sudo_local.template"
"$script" --pam-dir "$active_fixture" --dry-run >"$work/active-template-plan"
[ ! -e "$active_fixture/sudo_local" ]
grep -q "Planned destination: $active_fixture/sudo_local" "$work/active-template-plan"
grep -q 'auth sufficient pam_tid.so' "$work/active-template-plan"
"$script" --pam-dir "$active_fixture" --apply >/dev/null
cmp "$active_fixture/sudo_local.template" "$active_fixture/sudo_local"
mode=$(stat -c '%a' "$active_fixture/sudo_local" 2>/dev/null || stat -f '%Lp' "$active_fixture/sudo_local")
[ "$mode" = 600 ]
options_fixture=$work/options-template
mkdir "$options_fixture"
options_fixture=$(cd "$options_fixture" && pwd -P)
printf 'auth include sudo_local\n' >"$options_fixture/sudo"
printf '# auth sufficient pam_tid.so touch_timeout=30\n' >"$options_fixture/sudo_local.template"
"$script" --pam-dir "$options_fixture" --apply >/dev/null
grep -q '^auth sufficient pam_tid[.]so touch_timeout=30$' "$options_fixture/sudo_local"
race_fixture=$work/race-template
mkdir "$race_fixture"
race_fixture=$(cd "$race_fixture" && pwd -P)
printf 'auth include sudo_local\n' >"$race_fixture/sudo"
printf 'auth sufficient pam_tid.so\n' >"$race_fixture/sudo_local.template"
race_bin=$work/race-bin
mkdir "$race_bin"
real_cp=$(command -v cp)
cat >"$race_bin/cp" <<'EOF'
#!/bin/sh
if [ "$#" -eq 2 ] && [ "$1" = "$RACE_TEMPLATE" ] && [ "${2##*/}" = original ]; then
	printf '# Template changed during snapshot\n' >"$RACE_TEMPLATE"
fi
exec "$REAL_CP" "$@"
EOF
chmod +x "$race_bin/cp"
RACE_TEMPLATE=$race_fixture/sudo_local.template REAL_CP=$real_cp PATH=$race_bin:$PATH \
	"$script" --pam-dir "$race_fixture" --apply >"$work/race-apply"
grep -q '^auth.*pam_tid[.]so' "$race_fixture/sudo_local"
link_fixture=$work/link-race
mkdir "$link_fixture"
link_fixture=$(cd "$link_fixture" && pwd -P)
printf 'auth include sudo_local\n' >"$link_fixture/sudo"
real_link=$(command -v link)
cat >"$race_bin/link" <<'EOF'
#!/bin/sh
if [ "$#" -eq 2 ] && [ "$2" = "$RACE_DESTINATION" ]; then
	mkdir "$RACE_DESTINATION"
fi
exec "$REAL_LINK" "$@"
EOF
chmod +x "$race_bin/link"
expect_status 2 env RACE_DESTINATION="$link_fixture/sudo_local" REAL_LINK="$real_link" PATH="$race_bin:$PATH" \
	"$script" --pam-dir "$link_fixture" --apply
[ -d "$link_fixture/sudo_local" ]
[ -z "$(find "$link_fixture/sudo_local" -mindepth 1 -print -quit)" ]
printf 'Passed: mode validation, dry-run, template and no-template setup, custom rules, idempotency, options, rejected-policy preservation, symlink preservation, and exclusive creation.\n'
