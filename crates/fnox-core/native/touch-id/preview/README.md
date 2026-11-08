# Fnox verification preview

A standalone developer preview for designing and tweaking the [Fnox Touch ID UI](../../../../../docs/guide/touch-id-preview.md). It shows configurable synthetic request metadata and simulates approval by default. An explicit system mode verifies the current user through the platform API. **Neither mode reads credentials, starts a proxy, or grants a reusable authorization lease.**

## Requirements

| Purpose              | Version                                 |
| -------------------- | --------------------------------------- |
| Local `.mts` scripts | Node 22.18.0+; Node 23 requires 23.6.0+ |
| Recommended          | Node 26.13.0 LTS                        |
| CI                   | Node 26                                 |

CMake accepts Node.js 22.18.0+ (23.x requires 23.6.0+); Node.js 26 LTS is the recommended current release, not a build requirement. macOS builds target macOS 14+ and require the macOS 26 SDK for `NSGlassEffectView` and CMake 3.25+. Older systems use a standard opaque AppKit view. Reduce Transparency keeps the surface opaque; Reduce Motion limits animation.

Windows and Linux builds use Qt 6 Widgets and SVG. Linux also requires Qt D-Bus. Windows builds require MSVC and the Windows 11 SDK.

## Environment variables

These optional environment variables configure the preview process:

| Variable                         | Values and effect                                                                          |
| -------------------------------- | ------------------------------------------------------------------------------------------ |
| `FNOX_PREVIEW_AUTH`              | `simulate` (default) simulates approval; `system` uses the platform's native verification. |
| `FNOX_PREVIEW_MODE`              | `screenshot` hides preview labels and simulation hints; unset shows them.                  |
| `FNOX_PREVIEW_APPEARANCE`        | `light` or `dark` overrides system appearance; unset follows the system.                   |
| `FNOX_PREVIEW_CREDENTIAL_NAME`   | Displayed sample credential name; default `EXAMPLE_SECRET`.                                |
| `FNOX_PREVIEW_CREDENTIAL_SOURCE` | Displayed sample provider; default `Example provider`.                                     |
| `FNOX_PREVIEW_EXECUTABLE`        | Displayed sample executable path; default `/usr/local/bin/example-command`.                |
| `FNOX_PREVIEW_COMMAND`           | Displayed sample command; default `fnox exec -- ./example.sh`.                             |
| `FNOX_PREVIEW_PROJECT_DIRECTORY` | Displayed sample project directory; default `/workspace/example`.                          |

The metadata variables only change synthetic display values; the preview never reads Fnox configuration or credentials.

## Build and run

### macOS

```sh
cmake -S crates/fnox-core/native/touch-id/preview -B /tmp/fnox-touch-id-build -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/fnox-touch-id-build --target fnox-touch-id-preview --parallel 4
open /tmp/fnox-touch-id-build/fnox-touch-id-preview.app
```

Press **Shift+Return** to simulate approval. Cancel or Escape closes the panel. Details shows request metadata; long command and project values are shortened on screen, while their copy buttons copy the complete sanitized values.

To verify with actual Touch ID, run the executable directly:

```sh
FNOX_PREVIEW_AUTH=system /tmp/fnox-touch-id-build/fnox-touch-id-preview.app/Contents/MacOS/fnox-touch-id-preview
```

macOS presents its own authentication dialog. Only biometric success starts the approval animation. Shift+Return cannot approve a system request, and unavailable biometrics or cancellation never fall back to simulation. Success exits with status 0; unsuccessful verification exits with status 1; invalid authentication configuration exits with status 2.

### Windows and Linux

The portable Qt 6 Widgets presentation uses opaque surfaces, the shared theme, and sample metadata. It uses a static success mark; it does not reproduce the macOS crawl animation, Liquid Glass, or spring physics.

```sh
cmake -S crates/fnox-core/native/touch-id/preview -B build/preview -DCMAKE_BUILD_TYPE=Debug
cmake --build build/preview --config Debug --target fnox-touch-id-preview
```

Set `CMAKE_PREFIX_PATH` to the Qt installation if CMake cannot find it. The executable is in the build directory (under `Debug` with Visual Studio). The same `FNOX_PREVIEW_AUTH=system` option enables native verification:

- **Windows 11 (build 22000+):** the desktop Windows Hello API owns the prompt. Windows may offer PIN, face, or fingerprint verification; this is not fingerprint-only authentication.
- **Linux:** fprintd verifies the current user's enrolled fingerprint over the system D-Bus. The app displays instructions because fprintd has no universal authentication window. A supported reader, enrollment, a desktop session, and existing policy permissions are required. The preview does not change PAM or polkit configuration.

Windows/Linux hardware verification has not been tested on this macOS development machine. CI builds and simulated smoke checks cannot establish that hardware verification works on a user's device.

## Appearance and captures

Human preview mode shows a Preview label; on macOS, it alternates the Touch ID instruction with the simulation shortcut in a fixed position. Screenshot mode changes presentation only; it never enables real authentication. Published captures must identify the UI as a prototype. Actual macOS captures are hosted separately and are not included in this source tree. No Windows/Linux captures are claimed.

## Theme and assets

`../theme.mts` defines the palette and derives light mode using the [OKLab rules](../THEME.md). CMake generates headers in the build directory.

The unit suite is for regression checks, not launching the preview. CI runs it when preview files change. Run locally after code changes:

```sh
node --test test/native/touch-id/*.test.mts test/native/touch-id-preview/*.test.mts
```

Tests cover color math, animation, SVG parsing, header generation, and signing failures. They do not check appearance; inspect the preview after UI changes.

To optimize edited SVG assets:

`aube-lock.yaml` pins SVGO to 4.1.0; install the locked dependency before running it.

```sh
aube install --frozen-lockfile
aube exec -- svgo --config crates/fnox-core/native/touch-id/svgo.config.mjs -f crates/fnox-core/native/touch-id/assets
```

## Signing and production

The optional signing workflow builds from trusted `main`, signs and notarizes the universal macOS preview, then uploads it. It does not affect CLI releases and has not been run with maintainer credentials. Windows and Linux packaging remain future work.

Platform verification establishes user presence only. Production credential access must bind protected storage to the approved operation and requesting process. Never use this demo's result or exit code to authorize access.

## Signing and production boundary

The optional `Sign macOS verification preview` workflow builds a universal app from trusted upstream `main`, signs it with Fnox's existing Developer ID identity, notarizes and staples it, and uploads an artifact. It reuses the certificate and App Store Connect secret names from `release.yml`. It does not modify CLI releases or sign arbitrary pull-request code. The workflow has not been run with maintainer credentials; their presence and validity cannot be inferred from YAML references.

Fnox and mise already sign their CLI binaries. Neither existing CLI pipeline packages this app. Windows/Linux distribution signing and packaging remain follow-up work.

A successful platform verification only demonstrates the user's presence. Production credential access must bind the approved operation to protected storage and the requesting process. On macOS, the protected Keychain operation must use the appropriate access control and authentication context. Do not use this demo's result or exit status as a credential authorization mechanism.
