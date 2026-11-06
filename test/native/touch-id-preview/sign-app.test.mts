import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(
  new URL("../../../native/touch-id-preview/sign-app.sh", import.meta.url),
);
// The script uses macOS tools. No test invokes real signing or contacts Apple.
for (const verdict of [
  "Accepted",
  "Invalid",
  "submit-error",
  "staple-error",
  "missing-credentials",
]) {
  test(
    `signing script handles ${verdict} without publishing an unverified archive`,
    { skip: process.platform === "win32" },
    () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), "fnox-sign-test-"));
      try {
        const bin = path.join(root, "bin");
        fs.mkdirSync(bin);
        fs.mkdirSync(
          path.join(root, "build/preview/fnox-touch-id-preview.app"),
          { recursive: true },
        );
        const log = path.join(root, "calls");
        const stub = `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const tool = path.basename(process.argv[1]);
const args = process.argv.slice(2);
fs.appendFileSync(process.env.TEST_LOG, JSON.stringify([tool, ...args]) + '\\n');
if (tool === 'ditto') fs.writeFileSync(args.at(-1), 'archive');
if (tool === 'plutil') process.stdout.write(String(JSON.parse(fs.readFileSync(args.at(-1), 'utf8'))[args[1]]));
if (tool === 'xcrun' && args[0] === 'notarytool' && args[1] === 'submit') {
  if (process.env.TEST_VERDICT === 'submit-error') process.exit(1);
  process.stdout.write(JSON.stringify({ status: process.env.TEST_VERDICT === 'Invalid' ? 'Invalid' : 'Accepted', id: 'test-submission' }));
}
if (tool === 'xcrun' && args[0] === 'stapler' && process.env.TEST_VERDICT === 'staple-error') process.exit(1);
`;
        for (const tool of ["codesign", "ditto", "xcrun", "plutil", "spctl"])
          fs.writeFileSync(path.join(bin, tool), stub, { mode: 0o755 });
        const result = spawnSync("bash", [script], {
          cwd: root,
          encoding: "utf8",
          env: {
            ...process.env,
            PATH: `${bin}${path.delimiter}${process.env.PATH}`,
            TEST_LOG: log,
            TEST_VERDICT: verdict,
            APPLE_API_KEY_P8:
              verdict === "missing-credentials"
                ? ""
                : Buffer.from("fake key").toString("base64"),
            APPLE_API_KEY_ID: "fake-id",
            APPLE_API_ISSUER_ID: "fake-issuer",
            GITHUB_SHA: "test-revision",
          },
        });
        const archive = path.join(root, "dist/fnox-touch-id-preview-macos.zip");
        if (verdict === "Accepted") {
          assert.equal(result.status, 0, result.stderr);
          assert.ok(fs.existsSync(archive));
          assert.equal(
            fs.readFileSync(path.join(root, "dist/REVISION"), "utf8"),
            "test-revision\n",
          );
        } else {
          assert.notEqual(result.status, 0);
          assert.ok(!fs.existsSync(archive));
        }
        const calls = fs.existsSync(log)
          ? fs
              .readFileSync(log, "utf8")
              .trim()
              .split("\n")
              .map((line) => JSON.parse(line) as string[])
          : [];
        const submit = calls.find(
          (call) => call[0] === "xcrun" && call[2] === "submit",
        );
        if (submit)
          assert.ok(!fs.existsSync(submit[submit.indexOf("--key") + 1]!));
        if (verdict === "Invalid")
          assert.ok(
            calls.some((call) => call[0] === "xcrun" && call[2] === "log"),
          );
        if (verdict === "Accepted") {
          const staple = calls.findIndex(
            (call) => call[0] === "xcrun" && call[2] === "staple",
          );
          const finalArchive = calls.findIndex(
            (call) =>
              call[0] === "ditto" &&
              call.at(-1) === "dist/fnox-touch-id-preview-macos.zip",
          );
          assert.ok(staple >= 0 && finalArchive > staple);
        }
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    },
  );
}
