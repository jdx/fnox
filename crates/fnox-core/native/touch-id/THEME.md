# Theme derivation

`theme.mts` is the source of truth. Dark mode is the approved source palette. Light mode is derived; there is no second hand-maintained palette. The generator emits the same values for the AppKit controls and fingerprint animation, so AppKit and animation share the palette. Dark-mode buttons retain their resting fill. Light-mode Cancel and detail-copy buttons have no fill and use a one-point outline matching their labels.

Generating the theme and running its tests use the [requirements in the preview README](README.md#requirements). CMake checks the local runtime before generating headers.

## Formula

`color.mts` first decodes hexadecimal sRGB into linear RGB using the standard sRGB transfer function, then converts linear RGB to OKLab. OKLab separates perceptual lightness (`L`) from chromatic coordinates (`a`, `b`).

The base light-mode transform is:

```text
L_light = 0.95 - 0.78 × L_dark + role_offset
a_light = 0.90 × a_dark
b_light = 0.90 × b_dark
```

The result is converted back to linear RGB, clamped to the displayable [0, 1] range, encoded as sRGB, and rounded to 8-bit channels. Clamping can change hue for colors outside the sRGB gamut; this is a simple palette transform, not full perceptual gamut mapping.

The intercept, scale, and chroma multiplier are named constants in `color.mts`. Role offsets and contrast limits live in `LIGHT_RULES` in `theme.mts`.

## Role rules

| Role                                | Derivation in light mode                                                                                            |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Resting fingerprint                 | Source Cancel text, lightness offset +0.16                                                                          |
| Incoming fingerprint line           | Source slate, offset −0.09                                                                                          |
| Retracting fingerprint line         | Source muted blue, offset −0.035                                                                                    |
| Ordinary accent text and copy icons | Source muted blue instead of source gold; darken until readable against the slate control reference (offset −0.035) |
| Heading and Cancel text             | Their own source color; darken until readable against the slate control reference (offset −0.035)                   |
| Ribbon border                       | Source border color; darken against the light matte                                                                 |
| Text shimmer                        | Source slate starting at offset −0.09; darken only enough to remain readable against the light matte                |
| Success circle and check            | Reuse the darker of the incoming and retracting blue states                                                         |
| Pressed text and ribbon fill        | Base transform of their respective source colors                                                                    |

The blue substitutions prevent gold from becoming brown in light mode. The success mark deliberately reuses the fingerprint's deepest blue rather than introducing black. Dark mode retains the approved blue-to-gold sequence.

## Contrast search

Relative luminance uses linear sRGB weights `(0.2126, 0.7152, 0.0722)`. Contrast is `(lighter + 0.05) / (darker + 0.05)`.

Starting at a role's offset, the generator lowers OKLab lightness in steps of 0.005 until the relevant pair reaches 4.5:1, down to an offset of −0.3. It throws if no candidate meets the target. The light matte reference is `#fcfbf8`; dark-mode filled controls use the generated resting fill. Light-mode text retains its conservative slate contrast reference and is also checked against the light matte. In light mode, Cancel and detail-copy buttons have no fill: its one-point outline uses the same color as its label, leaving the glass visible underneath. Dark-mode Cancel remains filled.

This checks the listed pairs of opaque colors. It is not a blanket accessibility claim for every pressed state, animation frame, antialiased edge, or desktop image visible through translucent glass. Native review on light and dark backdrops is still required.

## Tuning

Please tweak the colors to taste. Change `COLORS` for the dark source palette, or the named transform parameters and role offsets for light-mode derivation. Rebuild after changes. The ribbon sizing, shadow, and border constants are in `preview/approval.mm`.

Color edits do not change the captured fingerprint geometry, crawl/retraction path, or animation timing. `animation.mts` assigns semantic theme roles to those existing paths. Text shimmer has its own color role, preventing it from accidentally becoming identical to the base text.

Run the small theme/animation checks with:

```sh
node --test test/native/touch-id/*.test.mts
```
