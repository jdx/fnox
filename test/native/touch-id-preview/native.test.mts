import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  fingerprintNativeSamples,
  parseFingerprintRidges,
} from "../../../native/touch-id-preview/native.mts";
import {
  DARK_THEME,
  LIGHT_THEME,
} from "../../../native/touch-id-preview/theme.mts";

const svg = fs.readFileSync(
  new URL(
    "../../../native/touch-id-preview/assets/geometry.svg",
    import.meta.url,
  ),
  "utf8",
);
const flow = JSON.parse(
  fs.readFileSync(
    new URL(
      "../../../native/touch-id-preview/assets/flow.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("parsed geometry retains separate ridges, opposing arcs, and finite coordinates", () => {
  const paths = parseFingerprintRidges(svg);
  assert.equal(paths.length, flow.directions.length);
  const arcs = paths.filter((path) => path.kind === "arc");
  assert.equal(arcs.length, 2);
  assert.deepEqual(
    arcs.map((arc) => arc.clockwise),
    [false, true],
  );
  assert.ok(
    arcs.every((arc) => Number.isFinite(arc.start) && Number.isFinite(arc.end)),
  );
  for (const ridge of paths) {
    if (ridge.kind !== "path") continue;
    assert.equal(ridge.commands[0]!.kind, "M");
    assert.ok(
      ridge.commands
        .flatMap((command) => command.values)
        .every(Number.isFinite),
    );
  }
});

test("malformed geometry and incomplete flow fail before generation", () => {
  assert.throws(() => parseFingerprintRidges("<svg/>"));
  assert.throws(() => parseFingerprintRidges(svg.replace("C", "Q")));
  assert.throws(() => fingerprintNativeSamples({ ...flow, directions: [] }));
});

test("native sample tables preserve theme colors and reach full success in both themes", () => {
  const tables = fingerprintNativeSamples(flow);
  assert.equal(tables.length, 2);
  for (const [index, theme] of [LIGHT_THEME, DARK_THEME].entries()) {
    const frames = tables[index]!;
    assert.equal(frames.length, 505);
    assert.ok(frames[0]!.extents.every((extent) => extent === 0));
    assert.ok(frames[0]!.tones.every((color) => color === theme.resting));
    assert.equal(frames.at(-1)!.ringColor, theme.success);
    assert.equal(frames.at(-1)!.checkColor, theme.check);
    assert.equal(frames.at(-1)!.checkOpacity, 1);
    assert.equal(frames.at(-1)!.ringSpan, Math.PI * 2);
  }
});
