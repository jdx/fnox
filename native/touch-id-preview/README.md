# Fnox verification preview

A standalone UI for the [Touch ID proposal](../../docs/proposals/macos-touch-id-approval.md). It shows sample request details and simulates approval by default. System mode verifies the user. Neither mode reads credentials, starts a proxy, or grants authorization.

## Requirements

| Purpose              | Version                                 |
| -------------------- | --------------------------------------- |
| Local `.mts` scripts | Node 22.18.0+; Node 23 requires 23.6.0+ |
| Recommended          | Node 26.13.0 LTS                        |
| CI                   | Node 26                                 |

CMake checks the local Node version. macOS builds target macOS 14+ and require the macOS 26 SDK for `NSGlassEffectView` and CMake 3.25+. Older systems use a standard opaque AppKit view. Reduce Transparency keeps the surface opaque; Reduce Motion limits animation.

Windows and Linux builds use Qt 6 Widgets and SVG. Linux also requires Qt D-Bus. Windows builds require MSVC and the Windows 11 SDK.

## Build and run

### macOS

```sh
cmake -S native/touch-id-preview -B /tmp/fnox-touch-id-build -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/fnox-touch-id-build --target fnox-touch-id-preview --parallel 4
open /tmp/fnox-touch-id-build/fnox-touch-id-preview.app
```

Press **Shift+Return** to simulate approval. Cancel or Escape closes the panel. Details shows sample metadata; labels copy values.

To use macOS Touch ID, run:

```sh
FNOX_PREVIEW_AUTH=system /tmp/fnox-touch-id-build/fnox-touch-id-preview.app/Contents/MacOS/fnox-touch-id-preview
```

Only successful biometric verification approves. Cancellation or unavailable biometrics never falls back to simulation. Exit codes: `0` success, `1` unsuccessful verification, `2` invalid configuration.

### Windows and Linux

```sh
cmake -S native/touch-id-preview -B build/preview -DCMAKE_BUILD_TYPE=Debug
cmake --build build/preview --config Debug --target fnox-touch-id-preview
```

Set `CMAKE_PREFIX_PATH` if CMake cannot find Qt. Use `FNOX_PREVIEW_AUTH=system` for platform verification:

- **Windows 11:** Windows Hello may use PIN, face, or fingerprint.
- **Linux:** fprintd verifies an enrolled fingerprint over D-Bus. A supported reader, enrollment, desktop session, and existing permissions are required. The preview does not change PAM or polkit.

Windows and Linux hardware verification is untested here. CI builds and simulation checks do not verify user hardware.

## Appearance and captures

Set `FNOX_PREVIEW_APPEARANCE=light` or `dark` to override the system. `FNOX_PREVIEW_MODE=screenshot` hides preview and simulation cues; it never enables authentication. Label captures as prototypes. macOS captures are on the [media branch](https://github.com/jdalton/fnox/tree/assets/touch-id-preview).

## Development

`theme.mts` defines the palette and derives light mode using the [OKLab rules](THEME.md). CMake generates headers in the build directory.

The unit suite is for regression checks, not launching the preview. CI runs it when preview files change. Run locally after code changes:

```sh
node --test test/native/touch-id-preview/*.test.mts
```

Tests cover color math, animation, SVG parsing, header generation, and signing failures. They do not check appearance; inspect the preview after UI changes.

To optimize edited SVG assets:

```sh
npx --yes svgo@4.0.0 --config native/touch-id-preview/svgo.config.mjs -f native/touch-id-preview/assets
```

The fingerprint uses 22 animated paths with absolute coordinates. Do not merge or convert them to relative paths.

## Signing and production

The optional signing workflow builds from trusted `main`, signs and notarizes the universal macOS preview, then uploads it. It does not affect CLI releases and has not been run with maintainer credentials. Windows and Linux packaging remain future work.

Platform verification establishes user presence only. Production credential access must bind protected storage to the approved operation and requesting process. Never use this demo's result or exit code to authorize access.
