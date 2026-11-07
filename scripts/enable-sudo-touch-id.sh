#!/bin/bash
# Opt-in macOS sudo Touch ID setup. Never run automatically during installation.
set -euo pipefail

describe='inspect or configure sudo Touch ID through an explicit PAM plan'
for argument in "$@"; do
	if [ "$argument" = --describe ]; then
		echo "$describe"
		exit 0
	fi
done

mode=check
pam_dir=/etc/pam.d
mode_seen=false
json_mode=false
for argument in "$@"; do
	if [ "$argument" = --json ]; then json_mode=true; fi
done
json_quote() {
	local value=$1
	local index character code
	printf '"'
	for ((index = 0; index < ${#value}; index++)); do
		character=${value:index:1}
		case "$character" in
		'"') printf '\\"' ;;
		\\) printf '\134\134' ;;
		$'\b') printf '\\b' ;;
		$'\f') printf '\\f' ;;
		$'\n') printf '\\n' ;;
		$'\r') printf '\\r' ;;
		$'\t') printf '\\t' ;;
		*)
			printf -v code '%d' "'$character"
			if [ "$code" -lt 32 ]; then
				printf '\\u%04x' "$code"
			else
				printf '%s' "$character"
			fi
			;;
		esac
	done
	printf '"'
}
emit_json_error() {
	printf '{"ok":false,"exitCode":2,"error":'
	json_quote "$1"
	printf '}\n'
}
fail() {
	if [ "$json_mode" = true ]; then
		emit_json_error "$1"
	else
		echo "$*" >&2
	fi
	exit 2
}
while [ "$#" -gt 0 ]; do
	case "$1" in
	--check | --dry-run | --apply)
		[ "$mode_seen" = false ] || {
			fail 'mode flags conflict; choose one of --check, --dry-run, or --apply.'
		}
		mode=${1#--}
		mode_seen=true
		;;
	--json)
		json_mode=true
		;;
	--pam-dir)
		[ "$#" -ge 2 ] || {
			fail '--pam-dir requires a directory path; add a path after the flag.'
		}
		pam_dir=$2
		shift
		;;
	--help)
		echo "$describe"
		echo
		echo 'Usage: enable-sudo-touch-id.sh [--check|--dry-run|--apply] [--json] [--pam-dir PAM_DIR]'
		echo '  --check     report whether Touch ID is configured'
		echo '  --dry-run   print the planned destination and contents'
		echo '  --apply     create the policy after validation'
		echo '  --json      print a structured result or error'
		echo '  --describe  print the one-line purpose'
		echo '  --pam-dir   use a PAM directory (for fixtures and tests)'
		echo '  --help      print this help'
		exit 0
		;;
	*)
		fail "option '$1' is not supported; use --check, --dry-run, --apply, --json, --describe, or --help."
		;;
	esac
	shift
done
policy_mode() {
	stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}
ensure_safe_policy_file() {
	local file=$1
	local require_root=$2
	local mode_value
	mode_value=$((8#$(policy_mode "$file")))
	[ $((mode_value & 022)) -eq 0 ] || fail "PAM policy '$file' is group- or world-writable; remove group and world write permissions."
	if [ "$live_pam_dir" = true ]; then
		if [ "$require_root" = true ]; then
			[ "$(stat -f %u "$file")" = 0 ] || fail "PAM policy '$file' is not owned by root; restore root ownership before applying."
		fi
		# macOS exposes policy ACL entries as extra lines in `ls -le`.
		# shellcheck disable=SC2012
		if [ "$(ls -le "$file" | wc -l)" -gt 1 ]; then
			fail "PAM policy '$file' has an ACL; remove the ACL before applying."
		fi
	fi
}
[ -d "$pam_dir" ] && [ ! -L "$pam_dir" ] || fail "--pam-dir '$pam_dir' must name an existing, non-symlink directory; choose a real directory."
pam_dir=$(cd "$pam_dir" && pwd -P)
live_pam_dir=false
if [ "$pam_dir" = /private/etc/pam.d ] || [ "$pam_dir" = /etc/pam.d ]; then
	live_pam_dir=true
	[ "$(uname -s)" = Darwin ] || fail "PAM directory '$pam_dir' is a live system path; use this setup only on macOS."
	if [ "$mode" = apply ]; then
		[ "$EUID" -eq 0 ] || fail 'Live --apply requires root; review --dry-run, then run sudo ./scripts/enable-sudo-touch-id.sh --apply.'
		[ "$(stat -f %u "$pam_dir")" = 0 ] || fail "Live PAM directory '$pam_dir' is not owned by root; restore root ownership before applying."
	fi
else
	[ "$EUID" -ne 0 ] || fail "Fixture directory '$pam_dir' is being used as root; run fixture tests as a non-root user."
fi
sudo_config=$pam_dir/sudo
local_config=$pam_dir/sudo_local
template=$pam_dir/sudo_local.template
for file in "$sudo_config" "$local_config" "$template"; do
	[ ! -L "$file" ] || fail "PAM path '$file' is a symbolic link; replace it with a regular file."
	if [ -e "$file" ]; then [ -f "$file" ] || fail "PAM path '$file' is not a regular file; replace it with a regular file."; fi
done
[ -f "$sudo_config" ] || fail "PAM configuration '$sudo_config' is missing; restore the system sudo configuration."
set +e
awk '
  { sub(/[[:space:]]*#.*/, "", $0) }
  $1 == "auth" && $2 == "include" && $3 == "sudo_local" {
    found=1
    if (unsafe) unsafe_before_include=1
    next
  }
  !found && $1 == "auth" && $2 != "optional" && $2 != "sufficient" { unsafe=1 }
  END { if (!found) exit 1; if (unsafe_before_include) exit 2 }
' "$sudo_config"
sudo_order_status=$?
set -e
[ "$sudo_order_status" -ne 1 ] || fail "PAM configuration '$sudo_config' does not include sudo_local; add the include after reviewing the system policy."
[ "$sudo_order_status" -ne 2 ] || fail "PAM configuration '$sudo_config' includes sudo_local after a credential rule; move the include before that rule or edit the policy manually."

source_file=$local_config
existed=true
source_present=true
if [ ! -f "$source_file" ]; then
	existed=false
	source_file=$template
	[ -f "$source_file" ] || source_present=false
fi

work=
staged=
if [ "$mode" != check ]; then
	if [ "$existed" = false ] && [ "$source_present" = true ]; then
		ensure_safe_policy_file "$source_file" true
	fi
	work=$(mktemp -d)
	trap 'rm -rf "$work"; if [ -n "$staged" ]; then rm -f "$staged"; fi' EXIT
	if [ "$source_present" = true ]; then cp "$source_file" "$work/original"; else : >"$work/original"; fi
	classification_file=$work/original
else
	classification_file=$source_file
fi

# Return 0 for one conventional active rule, 1 for absent, 2 for ambiguous rules.
if [ "$source_present" = true ]; then
	set +e
	awk '
    { sub(/[[:space:]]*#.*/, "", $0) }
    /^[[:space:]]*$/ { next }
    /pam_tid[.]so/ {
      if ($1 == "auth" && $2 == "sufficient" && $3 == "pam_tid.so") count++
      else bad=1
    }
    END { if (bad || count > 1) exit 2; exit count == 1 ? 0 : 1 }
  ' "$classification_file"
	status=$?
	set -e
else
	status=1
fi
[ "$status" -le 1 ] || fail "PAM policy '$classification_file' has ambiguous Touch ID rules; review and correct the rules manually."
if [ "$source_present" = true ] && [ "$status" = 0 ]; then
	set +e
	awk '
    { sub(/[[:space:]]*#.*/, "", $0) }
    /^[[:space:]]*$/ { next }
    $1 == "auth" {
      if ($3 == "pam_tid.so") { found=1; next }
      if (!found && $2 != "optional" && $2 != "sufficient") unsafe=1
    }
    END { if (unsafe || !found) exit 1 }
  ' "$classification_file"
	order_status=$?
	set -e
	[ "$order_status" = 0 ] || fail "PAM policy '$classification_file' places Touch ID after a blocking authentication rule; move the Touch ID rule earlier or edit the policy manually."
fi
if [ "$mode" = check ]; then
	if [ "$existed" = true ] && [ "$status" = 0 ]; then
		if [ "$json_mode" = true ]; then
			printf '{"ok":true,"exitCode":0,"data":{"configured":true,"interactiveAuthenticationVerified":false}}\n'
		else
			echo 'Touch ID for sudo is configured. Interactive authentication has not been verified.'
		fi
		exit 0
	fi
	if [ "$json_mode" = true ]; then
		printf '{"ok":true,"exitCode":1,"data":{"configured":false}}\n'
	else
		echo 'Touch ID for sudo is not configured.'
	fi
	exit 1
fi
if [ "$existed" = true ] && [ "$status" = 0 ]; then
	if [ "$json_mode" = true ]; then
		printf '{"ok":true,"exitCode":0,"data":{"action":"none","configured":true}}\n'
	else
		echo 'Touch ID for sudo is already configured; no changes made.'
	fi
	exit 0
fi
if [ "$existed" = true ]; then
	fail "PAM policy '$local_config' exists without the standard Touch ID rule; review it and add 'auth sufficient pam_tid.so' manually."
fi

if [ "$source_present" = true ]; then
	set +e
	awk '
    /^[[:space:]]*#/ {
      if ($0 ~ /^[[:space:]]*#[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_tid[.]so([[:space:]]|$)/) {
        if (auth_seen) unsafe=1
        placeholder=1
      }
      next
    }
    $1 == "auth" {
      if ($3 == "pam_tid.so") {
        if (auth_seen) unsafe=1
        found=1
      }
      auth_seen=1
    }
    END { if (unsafe || (!found && !placeholder && auth_seen)) exit 1 }
  ' "$classification_file"
	order_status=$?
	set -e
	[ "$order_status" = 0 ] || fail "PAM template '$classification_file' places another authentication rule first; move the Touch ID rule earlier or edit the template manually."
fi

awk -v already_enabled="$status" '
  BEGIN { line="auth       sufficient     pam_tid.so"; enabled=(already_enabled == 0) }
  $1 == "auth" && $2 == "sufficient" && $3 == "pam_tid.so" { enabled=1 }
  /^[[:space:]]*#[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_tid[.]so([[:space:]]|$)/ && !enabled {
    sub(/^[[:space:]]*#[[:space:]]*/, "")
    print
    enabled=1
    next
  }
  { print }
  END { if (!enabled) print line }
' "$work/original" >"$work/proposed"
if [ "$json_mode" = true ] && [ "$mode" = dry-run ]; then
	proposed_contents=$(
		cat "$work/proposed"
		printf '.'
	)
	proposed_contents=${proposed_contents%.}
	printf '{"ok":true,"exitCode":0,"data":{"action":"create","destination":'
	json_quote "$local_config"
	printf ',"proposedContents":'
	json_quote "$proposed_contents"
	printf '}}\n'
elif [ "$json_mode" = false ]; then
	echo "Planned destination: $local_config"
	echo 'Proposed sudo_local contents:'
	cat "$work/proposed"
fi
[ "$mode" = apply ] || exit 0

# Apply only by exclusive creation; never replace an existing local policy.
[ ! -L "$local_config" ] && [ ! -L "$source_file" ] || fail "PAM path '$local_config' or '$source_file' became a symbolic link during planning; inspect the paths and run again."
if [ "$source_present" = true ]; then
	cmp -s "$source_file" "$work/original" || fail "PAM source '$source_file' changed during planning; review it and run again."
else
	[ ! -e "$local_config" ] && [ ! -e "$template" ] || fail "PAM paths '$local_config' or '$template' changed during planning; review them and run again."
fi
staged=$(mktemp "$pam_dir/.fnox-sudo-local.XXXXXX")
if [ "$source_present" = true ]; then
	cp -p "$source_file" "$staged"
	cat "$work/proposed" >"$staged"
else
	cat "$work/proposed" >"$staged"
	chmod 644 "$staged"
fi
if [ "$source_present" = true ]; then
	cmp -s "$source_file" "$work/original" || fail "PAM source '$source_file' changed during staging; review it and run again."
	if [ "$existed" = false ]; then
		if [ "$mode" = apply ]; then
			ensure_safe_policy_file "$staged" true
		else
			ensure_safe_policy_file "$staged" false
		fi
	fi
fi
link "$staged" "$local_config" || fail "PAM destination '$local_config' could not be created; check its permissions and inspect the path."
rm "$staged"
staged=
if [ "$json_mode" = true ]; then
	printf '{"ok":true,"exitCode":0,"data":{"action":"created","destination":'
	json_quote "$local_config"
	printf '}}\n'
elif [ "$source_present" = true ]; then
	echo 'Created sudo_local from the system template.'
else
	echo 'Created sudo_local; neither sudo_local nor its template existed.'
fi
if [ "$json_mode" = false ]; then
	echo 'Touch ID for sudo is configured. Verify interactively with: sudo -k && sudo -v'
fi
