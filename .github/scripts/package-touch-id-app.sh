#!/bin/bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 <fnox-binary> <developer-id-profile> <signing-identity> <output-directory>" >&2
	exit 2
fi

binary="$1"
profile="$2"
identity="$3"
output_directory="$4"

if [[ ! -x "$binary" ]]; then
	echo "fnox executable not found or not executable: $binary" >&2
	exit 1
fi
if [[ ! -f "$profile" ]]; then
	echo "Developer ID provisioning profile not found: $profile" >&2
	exit 1
fi

mkdir -p "$output_directory"
app="$output_directory/Fnox.app"
if [[ -e "$app" ]]; then
	echo "refusing to replace existing bundle: $app" >&2
	exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
security cms -D -i "$profile" >"$work/profile.plist"
python3 - "$work/profile.plist" "$work/entitlements.plist" "$work/bundle-id" "$work/keychain-group" <<'PY'
import os
import plistlib
import sys

profile_path, entitlements_path, bundle_path, group_path = sys.argv[1:]
with open(profile_path, "rb") as source:
    profile = plistlib.load(source)
entitlements = profile.get("Entitlements", {})
team = profile.get("TeamIdentifier", [None])[0]
application_id = entitlements.get("com.apple.application-identifier") or entitlements.get("application-identifier")
if not team or not application_id or not application_id.startswith(team + "."):
    raise SystemExit("profile must contain a team-matched explicit macOS application identifier")
bundle_id = application_id[len(team) + 1:]
if not bundle_id or "*" in bundle_id:
    raise SystemExit("profile must contain an explicit application identifier")
expected_bundle_id = os.environ.get("FNOX_TOUCH_ID_HELPER_IDENTIFIER", "dev.jdx.fnox")
if bundle_id != expected_bundle_id:
    raise SystemExit(f"profile application identifier must be {expected_bundle_id}")
group = f"{team}.{bundle_id}"
allowed_groups = entitlements.get("keychain-access-groups", [])
if not any(group == allowed or (allowed.endswith(".*") and group.startswith(allowed[:-1])) for allowed in allowed_groups):
    raise SystemExit(f"profile does not authorize Keychain access group {group}")
entitlements["keychain-access-groups"] = [group]
with open(entitlements_path, "wb") as destination:
    plistlib.dump(entitlements, destination, fmt=plistlib.FMT_XML)
with open(bundle_path, "w") as destination:
    destination.write(bundle_id)
with open(group_path, "w") as destination:
    destination.write(group)
PY
bundle_identifier="$(cat "$work/bundle-id")"
keychain_group="$(cat "$work/keychain-group")"

mkdir -p "$app/Contents/MacOS"
cp "$binary" "$app/Contents/MacOS/fnox"
cp "$profile" "$app/Contents/embedded.provisionprofile"
cat >"$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>fnox</string>
  <key>CFBundleIdentifier</key><string>$bundle_identifier</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Fnox</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>FNOXKeychainAccessGroup</key><string>$keychain_group</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST

codesign --force --timestamp --options runtime --sign "$identity" \
	--entitlements "$work/entitlements.plist" --generate-entitlement-der "$app"
codesign --verify --deep --strict --verbose=2 "$app"
echo "$app"
