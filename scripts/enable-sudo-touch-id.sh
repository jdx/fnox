#!/bin/bash
# Opt-in macOS sudo Touch ID setup. Never run automatically during installation.
set -euo pipefail

mode=check
pam_dir=/etc/pam.d
mode_seen=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check|--dry-run|--apply)
      [ "$mode_seen" = false ] || { echo 'Choose only one of --check, --dry-run, or --apply.' >&2; exit 2; }
      mode=${1#--}
      mode_seen=true
      ;;
    --pam-dir) [ "$#" -ge 2 ] || { echo 'Missing --pam-dir value' >&2; exit 2; }; pam_dir=$2; shift ;;
    --help) echo 'Usage: enable-sudo-touch-id.sh [--check|--dry-run|--apply] [--pam-dir FIXTURE_DIR]'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
fail() { echo "$*" >&2; exit 2; }
[ -d "$pam_dir" ] && [ ! -L "$pam_dir" ] || fail 'PAM directory must be a real directory.'
pam_dir=$(cd "$pam_dir" && pwd -P)
if [ "$pam_dir" = /private/etc/pam.d ] || [ "$pam_dir" = /etc/pam.d ]; then
  [ "$(uname -s)" = Darwin ] || fail 'Live setup is supported only on macOS.'
  if [ "$mode" = apply ]; then
    [ "$EUID" -eq 0 ] || fail 'Review --dry-run first, then run this script with sudo --apply.'
    [ "$(stat -f %u "$pam_dir")" = 0 ] || fail 'The system PAM directory must be owned by root.'
  fi
else
  [ "$EUID" -ne 0 ] || fail 'Do not run fixture-directory operations as root.'
fi
sudo_config=$pam_dir/sudo
local_config=$pam_dir/sudo_local
template=$pam_dir/sudo_local.template
for file in "$sudo_config" "$local_config" "$template"; do
  [ ! -L "$file" ] || fail "Refusing symbolic link: $file"
  if [ -e "$file" ]; then [ -f "$file" ] || fail "Not a regular file: $file"; fi
done
[ -f "$sudo_config" ] || fail 'Missing sudo PAM configuration.'
awk '$1 == "auth" && $2 == "include" && $3 == "sudo_local" { found=1 } END { exit !found }' "$sudo_config" ||
  fail 'The sudo PAM configuration does not include sudo_local; no changes made.'

source_file=$local_config
existed=true
source_present=true
if [ ! -f "$source_file" ]; then
  existed=false
  source_file=$template
  [ -f "$source_file" ] || source_present=false
fi
# Return 0 for one conventional active rule, 1 for absent, 2 for ambiguous rules.
if [ "$source_present" = true ]; then
  set +e
  awk '
    /^[[:space:]]*#/ { next }
    /pam_tid[.]so/ {
      if ($1 == "auth" && $2 == "sufficient" && $3 == "pam_tid.so") count++
      else bad=1
    }
    END { if (bad || count > 1) exit 2; exit count == 1 ? 0 : 1 }
  ' "$source_file"
  status=$?
  set -e
else
  status=1
fi
[ "$status" -le 1 ] || fail 'Ambiguous Touch ID PAM rules; review them manually. No changes made.'
if [ "$mode" = check ]; then
  if [ "$existed" = true ] && [ "$status" = 0 ]; then
    echo 'Touch ID for sudo is configured. Interactive authentication has not been verified.'
    exit 0
  fi
  echo 'Touch ID for sudo is not configured.'
  exit 1
fi
if [ "$existed" = true ] && [ "$status" = 0 ]; then
  echo 'Touch ID for sudo is already configured; no changes made.'
  exit 0
fi

work=$(mktemp -d)
staged=
trap 'rm -rf "$work"; if [ -n "$staged" ]; then rm -f "$staged"; fi' EXIT
if [ "$source_present" = true ]; then cp "$source_file" "$work/original"; else : > "$work/original"; fi
awk -v already_enabled="$status" '
  BEGIN { line="auth       sufficient     pam_tid.so"; enabled=(already_enabled == 0) }
  $1 == "auth" && $2 == "sufficient" && $3 == "pam_tid.so" { enabled=1 }
  /^[[:space:]]*#[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_tid[.]so([[:space:]]|$)/ && !enabled {
    print line; enabled=1; next
  }
  { print }
  END { if (!enabled) print line }
' "$work/original" > "$work/proposed"
# Display the exact change before committing it. diff's exit 1 means differences.
set +e
if [ "$source_present" = true ]; then diff -u "$source_file" "$work/proposed"; else diff -u /dev/null "$work/proposed"; fi
diff_status=$?
set -e
[ "$diff_status" -le 1 ] || fail 'Unable to display proposed changes.'
[ "$mode" = apply ] || exit 0

# Refuse a concurrent edit or replacement between planning and applying.
[ ! -L "$local_config" ] && [ ! -L "$source_file" ] || fail 'PAM file changed during planning.'
if [ "$source_present" = true ]; then
  cmp -s "$source_file" "$work/original" || fail 'PAM file changed during planning; run again.'
else
  [ ! -e "$local_config" ] && [ ! -e "$template" ] || fail 'PAM files changed during planning; run again.'
fi
staged=$(mktemp "$pam_dir/.fnox-sudo-local.XXXXXX")
if [ "$existed" = true ]; then
  cp -p "$local_config" "$staged"
  cat "$work/proposed" > "$staged"
else
  cat "$work/proposed" > "$staged"
  chmod 644 "$staged"
fi
if [ "$existed" = true ]; then
  backup=$(mktemp "$pam_dir/sudo_local.fnox-backup.XXXXXX")
  cp -p "$local_config" "$backup"
  echo "Original configuration backed up to: $backup"
else
  if [ "$source_present" = true ]; then
    echo 'Creating sudo_local from the system template; there was no original sudo_local.'
  else
    echo 'Creating sudo_local; neither sudo_local nor its template existed.'
  fi
fi
if [ "$existed" = true ]; then
  cmp -s "$local_config" "$work/original" || fail 'sudo_local changed during planning; run again.'
else
  [ ! -e "$local_config" ] || fail 'sudo_local appeared during planning; run again.'
fi
mv -f "$staged" "$local_config"
staged=
echo 'Touch ID for sudo is configured. Verify interactively with: sudo -k && sudo -v'
echo 'To undo, review subsequent edits before restoring the backup or removing the newly created sudo_local.'
