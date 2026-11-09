import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { optimize } from "svgo";
import {
  parseFingerprintRidges,
  svgoConfig,
  touchIdPaths,
} from "../../paths/touch-id.mts";

test("SVGO preserves independently animated geometry and is idempotent", () => {
  const svg = fs.readFileSync(touchIdPaths.assets.geometry, "utf8");
  const optimized = optimize(svg, svgoConfig).data;
  assert.deepEqual(
    parseFingerprintRidges(optimized),
    parseFingerprintRidges(svg),
  );
  assert.equal(optimize(optimized, svgoConfig).data, optimized);
  assert.ok(Buffer.byteLength(optimized) <= Buffer.byteLength(svg));
});
