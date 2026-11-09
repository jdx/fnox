import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  DARK_THEME,
  fingerprintNativeSamples,
  LIGHT_THEME,
  parseFingerprintRidges,
  touchIdPaths,
} from "../../paths/touch-id.mts";

const svg = fs.readFileSync(touchIdPaths.assets.geometry, "utf8");
const approvalPrompt = fs.readFileSync(touchIdPaths.approvalPrompt, "utf8");
const flow = JSON.parse(fs.readFileSync(touchIdPaths.assets.flow, "utf8"));

test("approval details bound display but copy complete sanitized command and project", () => {
  assert.match(
    approvalPrompt,
    /command = BoundedDisplayValue\(fullCommand, 80\)/,
  );
  assert.match(
    approvalPrompt,
    /project = BoundedDisplayValue\(fullProject, 80\)/,
  );
  assert.match(
    approvalPrompt,
    /NSString\* fullCommand = SafeDisplayValue\(command\)/,
  );
  assert.match(
    approvalPrompt,
    /NSString\* fullProject = SafeDisplayValue\(project\)/,
  );
  assert.match(
    approvalPrompt,
    /@"Command \(unverified\)",\s*command,\s*fullCommand/,
  );
  assert.match(
    approvalPrompt,
    /@"Project \(unverified\)",\s*project,\s*fullProject/,
  );
  assert.match(approvalPrompt, /NSPasteboardTypeString/);
  assert.match(approvalPrompt, /@"Command \(unverified\)"/);
  assert.match(approvalPrompt, /@"Project \(unverified\)"/);
  assert.match(approvalPrompt, /NSString\* secret = BoundedDisplayValue/);
  assert.match(approvalPrompt, /Keychain service \(unverified\)/);
});

test("approval heading does not trust caller-supplied executable identity", () => {
  assert.match(approvalPrompt, /Unverified command: %@ · Allow access to %@\?/);
  assert.doesNotMatch(approvalPrompt, /Allow %@ to use %@\?/);
});

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
