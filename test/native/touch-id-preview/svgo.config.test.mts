import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { optimize } from "svgo";
import config from "../../../crates/fnox-core/native/touch-id-preview/svgo.config.mjs";
import { parseFingerprintRidges } from "../../../crates/fnox-core/native/touch-id-preview/native.mts";

test("SVGO preserves independently animated geometry and is idempotent", () => {
  const svg = fs.readFileSync(
    new URL(
      "../../../crates/fnox-core/native/touch-id-preview/assets/geometry.svg",
      import.meta.url,
    ),
    "utf8",
  );
  const optimized = optimize(svg, config).data;
  assert.deepEqual(
    parseFingerprintRidges(optimized),
    parseFingerprintRidges(svg),
  );
  assert.equal(optimize(optimized, config).data, optimized);
  assert.ok(Buffer.byteLength(optimized) <= Buffer.byteLength(svg));
});
