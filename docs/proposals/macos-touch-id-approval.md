# Proposal: native macOS Touch ID approval

**Status:** design proposal for maintainer feedback

## Current behavior

fnox already supports Touch ID for encrypted sync caches through Apple's Secure Enclave using [`age-plugin-se`](../guide/sync.md#apple-secure-enclave-touch-id). The plugin owns its own authentication prompt. fnox's batch sync format and optional daemon cache reduce repeated unlocks, but fnox does not show a branded approval panel with the command and credential context.

The existing `keychain` provider uses the platform keyring abstraction and does not let a project request biometric access control. A native approval feature should add that as an opt-in macOS capability without replacing or wrapping the age plugin's separate prompt.

## Proposed first slice

Add an opt-in macOS keychain access policy for secrets stored by fnox. When a protected item is needed, show a Fnox-branded approval panel containing the request context, then perform the protected Keychain operation using the same `LAContext`.

The operating system must enforce access to the protected item. Showing a Touch ID prompt before an ordinary keychain read is not sufficient: the protected read itself must use the authorization context. If Touch ID is unavailable, declined, or fails, the read fails closed.

Keep the new path optional and macOS-only. Existing provider behavior and the `age-plugin-se` flow remain unchanged. A later step could add a short-lived, scoped in-memory approval lease to reduce repeat prompts. The lease should be bounded, cleared when the daemon exits, and must not silently turn the daemon's existing idle timeout into a credential TTL.

## Request panel

Show only metadata needed to make the approval decision:

- command and project directory;
- active fnox profile;
- secret names and their provider;
- requested operation and, where available, the network destination or command receiving the value;
- whether approval applies to this read or a documented short-lived lease.

Never pass secret values to the UI. Bind an approval to one request and prevent it from being replayed for a different key, project, or operation. In headless sessions, do not launch a GUI; return a clear error and leave the normal provider flow available.

## macOS implementation questions

Apple's Local Authentication APIs support an `LAContext` for biometric policy evaluation, and Keychain access controls can use an authentication context for the protected operation. The implementation should use public APIs and one context for the visible approval and the protected item read. The included preview can simulate approval or explicitly request real platform verification. Neither mode authorizes a protected Keychain read.

The release workflow already imports the Developer ID certificate and signs and notarizes the macOS `fnox` binary. A separate app/helper bundle may require release packaging and signing changes, and the repository references the credentials used for Fnox releases; a new certificate does not appear to be the blocker. Maintainers should confirm whether to keep the panel in the signed executable or ship a separately signed helper before implementation.

References: [Apple Local Authentication](https://developer.apple.com/documentation/localauthentication), [Apple Keychain access-control flags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags), [`fnox` macOS release signing](https://github.com/jdx/fnox/blob/main/.github/workflows/release.yml).

## Runnable native preview

The [standalone preview](https://github.com/jdalton/fnox/blob/docs/touch-id-daemon-session/native/touch-id-preview/README.md) demonstrates a native macOS Liquid Glass approval dialog, request details, copy controls, keyboard hints, and fingerprint success animation in light and dark mode. Shift+Return simulates approval by default. Opt-in system mode uses the macOS-owned Touch ID prompt, with no keyboard bypass. Windows and Linux have an opaque Qt presentation with Windows Hello and fprintd adapters. All modes use sample metadata and do not read credentials or start a proxy.

Dark mode uses Fnox slate, blue, and gold. Light mode is derived from the dark palette with a perceptual color transform and contrast rules; its resting fingerprint is charcoal, its working states and success mark use blue, and its buttons have unfilled text-colored outlines. Dark-mode buttons retain their slate fill. The animation path and timing are independent of the palette.

**The colors are a starting point: please tweak them to taste.** Edit `native/touch-id-preview/theme.mts` to adjust the shared palette and light-mode derivation. The preview ribbon colors are selected in `preview/approval.mm`.

Production credential integration, OS-enforced Keychain access, and approval leases remain follow-up work. A separate manual workflow builds, signs, notarizes, and staples the macOS app from trusted upstream main using the existing release secret names. It has not been executed with maintainer credentials. The preview is not part of the CLI build or release workflow; Windows/Linux hardware verification and distribution also remain unverified.

## Maintainer feedback requested

1. Is an opt-in, OS-enforced biometric policy for fnox-managed Keychain items the right first slice?
2. Should the native panel live in the signed `fnox` executable or a separately signed helper?
3. What default approval-lease duration and scope would be acceptable, if a lease is added after the first slice?
