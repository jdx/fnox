import assert from "node:assert/strict";
import test from "node:test";
import {
  contrastRatio,
  luminance,
  transformLightColor,
} from "../../../native/touch-id-preview/color.mts";

test("sRGB luminance matches standard primary-color weights", () => {
  assert.equal(luminance("#ff0000"), 0.2126);
  assert.equal(luminance("#00ff00"), 0.7152);
  assert.equal(luminance("#0000ff"), 0.0722);
  assert.ok(Math.abs(luminance("#808080") - 0.2158605) < 0.000001);
});

test("contrast is symmetric and identical colors have ratio one", () => {
  for (const color of ["#000000", "#ffffff", "#323c4a", "#d4af37"]) {
    assert.equal(contrastRatio(color, color), 1);
    assert.equal(
      contrastRatio(color, "#ffffff"),
      contrastRatio("#ffffff", color),
    );
  }
});

test("lightness offsets move luminance monotonically and clamp to the gamut", () => {
  for (const color of ["#000000", "#ffffff", "#323c4a", "#637a8e", "#d4af37"]) {
    const darker = transformLightColor(color, -0.1);
    const lighter = transformLightColor(color, 0.1);
    assert.ok(luminance(darker) < luminance(lighter));
    assert.match(darker, /^#[0-9a-f]{6}$/);
    assert.equal(transformLightColor(color, 100), "#ffffff");
    assert.equal(transformLightColor(color, -100), "#000000");
  }
});
