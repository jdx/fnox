import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { generateHeaders } from "../../../native/touch-id-preview/build-header.mts";

const script = fileURLToPath(
  new URL("../../../native/touch-id-preview/build-header.mts", import.meta.url),
);

test("header command rejects missing output without creating artifacts", () => {
  assert.throws(() => generateHeaders(""));
  const missing = spawnSync(
    process.execPath,
    [script],
    { encoding: "utf8" },
  );
  assert.notEqual(missing.status, 0);
});

test("header generation is deterministic and works outside the repository directory", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "fnox-header-test-"));
  try {
    const paths = generateHeaders(directory);
    assert.deepEqual(paths.map((file) => path.basename(file)).sort(), [
      "detail-copy-icons.generated.h",
      "fingerprint-animation.generated.h",
      "theme.generated.h",
    ]);
    const before = paths.map((file) => fs.readFileSync(file));
    assert.ok(before.every((bytes) => bytes.length > 0));
    const run = spawnSync(
      process.execPath,
      [script, directory],
      { cwd: os.tmpdir(), encoding: "utf8" },
    );
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(
      paths.map((file) => fs.readFileSync(file)),
      before,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
