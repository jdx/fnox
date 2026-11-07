import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  clampFingerprintProgress,
  easeFingerprintProgress,
  fingerprintApprovalDurationMs,
  fingerprintCircleSpan,
  fingerprintDash,
  fingerprintFrame,
  fingerprintVisitedFrames,
  mixFingerprintColor,
  neutralFingerprintColor,
  parseFingerprintColor,
  sampleFingerprintFlow,
  FINGERPRINT_PALETTES,
} from "../../../crates/fnox-core/native/touch-id-preview/animation.mts";

const flow = JSON.parse(
  fs.readFileSync(
    new URL(
      "../../../crates/fnox-core/native/touch-id-preview/assets/flow.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("animation boundaries clamp malformed progress and preserve endpoints", () => {
  for (const input of [-1, NaN, Infinity])
    assert.equal(clampFingerprintProgress(input), 0);
  assert.equal(clampFingerprintProgress(2), 1);
  assert.equal(easeFingerprintProgress(0), 0);
  assert.equal(easeFingerprintProgress(0.5), 0.5);
  assert.equal(easeFingerprintProgress(1), 1);
  assert.equal(fingerprintCircleSpan(0), 0);
  assert.equal(fingerprintCircleSpan(4200), 2 * Math.PI);
  assert.ok(
    fingerprintApprovalDurationMs(true) < fingerprintApprovalDurationMs(),
  );
});

test("flow interpolates and holds only previously visited paths", () => {
  assert.equal(sampleFingerprintFlow([0, 1, 0], 0.25), 0.25);
  assert.equal(sampleFingerprintFlow([0, 1], 2), 0);
  assert.equal(sampleFingerprintFlow([0, 1], 2, true), 1);
  for (const position of [-1, Infinity, NaN])
    assert.equal(sampleFingerprintFlow([1], position), 0);
  assert.equal(sampleFingerprintFlow([], 0), 0);
  assert.deepEqual(
    fingerprintVisitedFrames([0, 0.5, 0.2, 1, 0]),
    [0, 0.5, 0.5, 1, 1],
  );
  assert.deepEqual(fingerprintDash(0.25, { fromEnd: false }), {
    length: 25,
    offset: 0,
  });
  assert.deepEqual(fingerprintDash(0.25, { fromEnd: true }), {
    length: 25,
    offset: -75,
  });
});

test("color mixing preserves endpoints and rejects invalid colors", () => {
  assert.deepEqual(parseFingerprintColor("#aB00FF"), [171, 0, 255]);
  assert.throws(() => parseFingerprintColor("#fff"), TypeError);
  assert.equal(mixFingerprintColor("#000000", "#ffffff", 0.5), "#808080");
  assert.equal(mixFingerprintColor("#123456", "#abcdef", 0), "#123456");
  assert.equal(mixFingerprintColor("#123456", "#abcdef", 1), "#abcdef");
  assert.equal(neutralFingerprintColor("#ffffff"), "#ffffff");
  assert.equal(neutralFingerprintColor("#000000"), "#000000");
});

test("all sampled frames stay bounded and end with a complete success mark", () => {
  const visited = flow.frames.map(fingerprintVisitedFrames);
  for (const palette of Object.values(FINGERPRINT_PALETTES)) {
    for (let time = 0; time <= 4200; time += 25) {
      const frame = fingerprintFrame(time, flow, visited, palette);
      assert.equal(frame.extents.length, 22);
      for (const value of [
        ...frame.extents,
        ...frame.visited,
        frame.progress,
        frame.eased,
        frame.checkOpacity,
      ])
        assert.ok(Number.isFinite(value) && value >= 0 && value <= 1);
      frame.extents.forEach((extent, i) =>
        assert.ok(frame.visited[i]! + 1e-8 >= extent),
      );
    }
    const final = fingerprintFrame(4200, flow, visited, palette);
    assert.equal(final.checkOpacity, 1);
    assert.equal(final.ringSpan, 2 * Math.PI);
    assert.deepEqual(final.checkEnd, [192, 99]);
  }
});
