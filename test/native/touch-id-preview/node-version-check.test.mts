import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const checkModule = fileURLToPath(
  new URL(
    "../../../native/touch-id-preview/node-version-check.cmake",
    import.meta.url,
  ),
);

test("CMake accepts Node versions with flag-free type stripping", () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "fnox-node-version-"),
  );
  try {
    const cases = [
      ["v22.17.9", false],
      ["v22.18.0", true],
      ["v23.0.0", false],
      ["v23.5.99", false],
      ["v23.6.0", true],
      ["v24.0.0", true],
      ["v26.0.0", true],
    ] as const;

    for (const [version, supported] of cases) {
      const script = path.join(directory, `${version}.cmake`);
      const cmakePath = checkModule
        .replaceAll("\\", "/")
        .replaceAll('"', '\\"');
      fs.writeFileSync(
        script,
        `include("${cmakePath}")\nfnox_require_typescript_node("${version}" "test node")\n`,
      );
      const result = spawnSync("cmake", ["-P", script], { encoding: "utf8" });
      assert.equal(
        result.status,
        supported ? 0 : 1,
        `${version}: ${result.stderr || result.stdout}`,
      );
      if (!supported) {
        const minimum = version.startsWith("v23.") ? "23.6+" : "22.18+";
        assert.ok(
          result.stderr.includes(`Requires Node.js ${minimum}`),
          `${version}: ${result.stderr}`,
        );
        assert.match(result.stderr, /Node\.js\s+26\.13\.0 LTS recommended/);
      }
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
