#!/bin/bash
set -euo pipefail
script=$(cd "$(dirname "$0")/../.." && pwd)/scripts/enable-sudo-touch-id.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fixture=$work/pam
mkdir "$fixture"
printf 'auth include sudo_local\nauth sufficient pam_smartcard.so\n' > "$fixture/sudo"
printf '# Local policy\n#auth sufficient pam_tid.so\nauth optional pam_custom.so\n' > "$fixture/sudo_local.template"
run() { "$script" --pam-dir "$fixture" "$@"; }
expect_status() {
  expected=$1; shift
  set +e
  "$@" > "$work/output" 2>&1
  actual=$?
  set -e
  [ "$actual" = "$expected" ] || { cat "$work/output"; echo "Expected $expected, got $actual" >&2; exit 1; }
}
expect_status 1 run --check
expect_status 2 run --check --dry-run
run --dry-run > "$work/plan"
[ ! -e "$fixture/sudo_local" ]
run --apply > "$work/apply"
run --check > /dev/null
[ "$(awk '$1=="auth" && $3=="pam_tid.so" {n++} END{print n}' "$fixture/sudo_local")" = 1 ]
grep -q 'pam_custom.so' "$fixture/sudo_local"
cp "$fixture/sudo_local" "$work/first"
run --apply > /dev/null
cmp "$fixture/sudo_local" "$work/first"
printf 'auth sufficient pam_tid.so\nauth sufficient pam_tid.so\n' > "$fixture/sudo_local"
expect_status 2 run --apply
printf 'auth required pam_tid.so\n' > "$fixture/sudo_local"
expect_status 2 run --apply
printf 'auth sufficient pam_tid.so touch_timeout=30\n' > "$fixture/sudo_local"
run --check > /dev/null
cp "$fixture/sudo_local" "$work/with-options"
run --apply > /dev/null
cmp "$fixture/sudo_local" "$work/with-options"
rm "$fixture/sudo_local"
ln -s "$fixture/sudo_local.template" "$fixture/sudo_local"
expect_status 2 run --apply
rm "$fixture/sudo_local"
printf 'auth optional pam_custom.so\n' > "$fixture/sudo_local"
chmod 600 "$fixture/sudo_local"
cp "$fixture/sudo_local" "$work/before"
run --apply > /dev/null
cmp "$work/before" "$fixture"/sudo_local.fnox-backup.*
mode=$(stat -f '%Lp' "$fixture/sudo_local" 2>/dev/null || stat -c '%a' "$fixture/sudo_local")
[ "$mode" = 600 ]
printf 'auth sufficient pam_smartcard.so\n' > "$fixture/sudo"
expect_status 2 run --apply
fresh_fixture=$work/no-template
mkdir "$fresh_fixture"
printf 'auth include sudo_local\n' > "$fresh_fixture/sudo"
"$script" --pam-dir "$fresh_fixture" --dry-run > "$work/no-template-plan"
[ ! -e "$fresh_fixture/sudo_local" ]
grep -q '^+auth.*pam_tid[.]so' "$work/no-template-plan"
"$script" --pam-dir "$fresh_fixture" --apply > /dev/null
grep -q '^auth.*pam_tid[.]so' "$fresh_fixture/sudo_local"
printf 'Passed: mode validation, dry run, template and no-template setup, custom rules, idempotency, options, duplicates, unexpected policy, symlink, backup, permission preservation, missing include.\n'
