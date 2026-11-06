#!/usr/bin/env bash
# Invoked only by the trusted-main signing workflow. Tests mock external tools.
set -euo pipefail
test -n "$APPLE_API_KEY_P8"
test -n "$APPLE_API_KEY_ID"
test -n "$APPLE_API_ISSUER_ID"
app=build/preview/fnox-touch-id-preview.app
codesign --force --options runtime --timestamp \
	--sign 'Developer ID Application: Jeffrey Dickey (4993Y37DX6)' "$app"
codesign --verify --strict --verbose=2 "$app"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '%s' "$APPLE_API_KEY_P8" | base64 --decode >"$work/key.p8"
chmod 600 "$work/key.p8"
ditto -c -k --keepParent "$app" "$work/submission.zip"
xcrun notarytool submit "$work/submission.zip" \
	--key "$work/key.p8" --key-id "$APPLE_API_KEY_ID" \
	--issuer "$APPLE_API_ISSUER_ID" --wait --timeout 30m \
	--output-format json >"$work/result.json"
cat "$work/result.json"
if [ "$(plutil -extract status raw -o - "$work/result.json")" != Accepted ]; then
	submission_id="$(plutil -extract id raw -o - "$work/result.json")"
	xcrun notarytool log "$submission_id" \
		--key "$work/key.p8" --key-id "$APPLE_API_KEY_ID" \
		--issuer "$APPLE_API_ISSUER_ID" || true
	exit 1
fi
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
mkdir -p dist
ditto -c -k --keepParent "$app" dist/fnox-touch-id-preview-macos.zip
shasum -a 256 dist/fnox-touch-id-preview-macos.zip >dist/SHA256SUMS
printf '%s\n' "$GITHUB_SHA" >dist/REVISION
