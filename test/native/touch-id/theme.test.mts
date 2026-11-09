import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  contrastRatio,
  DARK_THEME,
  fingerprintFrame,
  fingerprintVisitedFrames,
  FINGERPRINT_PALETTES,
  LIGHT_RULES,
  LIGHT_THEME,
  luminance,
  transformLightColor,
  touchIdPaths,
} from "../../paths/touch-id.mts";

test("color math rejects malformed inputs and uses standard luminance endpoints", () => {
  assert.equal(luminance("#000000"), 0);
  assert.equal(luminance("#ffffff"), 1);
  assert.equal(contrastRatio("#000000", "#ffffff"), 21);
  assert.throws(() => transformLightColor("white"), TypeError);
  assert.throws(() => transformLightColor("#ffff"), TypeError);
});

test("light roles satisfy their declared contrast backgrounds", () => {
  for (const role of [
    "accent",
    "highlight",
    "heading",
    "cancelText",
  ] as const) {
    assert.ok(
      contrastRatio(LIGHT_THEME[role], LIGHT_RULES.matte) >=
        LIGHT_RULES.minimumContrast,
      role,
    );
  }
  for (const role of ["border", "shimmer"] as const) {
    assert.ok(
      contrastRatio(LIGHT_THEME[role], LIGHT_RULES.matte) >=
        LIGHT_RULES.minimumContrast,
      role,
    );
  }
  assert.ok(luminance(LIGHT_THEME.shimmer) > luminance(LIGHT_THEME.accent));
});

test("approved dark palette and light success colors stay stable", () => {
  assert.deepEqual(FINGERPRINT_PALETTES.dark, [
    "#323c4a",
    "#637a8e",
    "#d4af37",
    "#e5bf52",
    "#edcc75",
  ]);
  assert.equal(LIGHT_THEME.resting, "#40403d");
  assert.ok(luminance(LIGHT_THEME.resting) > luminance(LIGHT_THEME.cancelText));
  assert.ok(contrastRatio(LIGHT_THEME.resting, LIGHT_RULES.matte) >= 4.5);
  assert.equal(LIGHT_THEME.success, "#4a5e6f");
  assert.equal(LIGHT_THEME.check, LIGHT_THEME.success);
});

test("animation and controls share consistent resting fills", () => {
  assert.equal(FINGERPRINT_PALETTES.light[0], LIGHT_THEME.resting);
  assert.equal(FINGERPRINT_PALETTES.dark[0], DARK_THEME.resting);
});

test("acceptance starts without an overlay and never recolors untouched ridges", () => {
  const flow = JSON.parse(fs.readFileSync(touchIdPaths.assets.flow, "utf8"));
  const visited = flow.frames.map(fingerprintVisitedFrames);
  for (const palette of Object.values(FINGERPRINT_PALETTES)) {
    const initial = fingerprintFrame(0, flow, visited, palette);
    assert.ok(initial.extents.every((value) => value === 0));
    for (const time of [0, 700, 1400, 2200, 2900]) {
      assert.ok(
        fingerprintFrame(time, flow, visited, palette).tones.every(
          (color) => color === palette[0],
        ),
      );
    }
  }
});
