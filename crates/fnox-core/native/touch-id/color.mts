// Standard sRGB transfer function and OKLab conversion matrices.
// See THEME.md for the derivation and design parameters.
export const LIGHTNESS_INTERCEPT = 0.95;
export const LIGHTNESS_SCALE = 0.78;
export const CHROMA_SCALE = 0.9;
const CONTRAST_LUMINANCE_OFFSET = 0.05;

export type Rgb = [number, number, number];
export function linearRgb(hex: string): Rgb {
  if (!/^#[0-9a-f]{6}$/i.test(hex))
    throw new TypeError(`Invalid color: ${hex}`);
  return hex
    .slice(1)
    .match(/../g)!
    .map((channel) => parseInt(channel, 16) / 255)
    .map((value) =>
      value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4,
    ) as Rgb;
}

export function transformLightColor(hex: string, lightnessOffset = 0): string {
  const rgb = linearRgb(hex);
  const [r, g, b] = rgb as [number, number, number];
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  const L =
    lightnessOffset +
    LIGHTNESS_INTERCEPT -
    LIGHTNESS_SCALE * (0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s);
  const a =
    CHROMA_SCALE * (1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s);
  const z =
    CHROMA_SCALE * (0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s);
  const ll = (L + 0.3963377774 * a + 0.2158037573 * z) ** 3;
  const mm = (L - 0.1055613458 * a - 0.0638541728 * z) ** 3;
  const ss = (L - 0.0894841775 * a - 1.291485548 * z) ** 3;
  return (
    "#" +
    [
      4.0767416621 * ll - 3.3077115913 * mm + 0.2309699292 * ss,
      -1.2684380046 * ll + 2.6097574011 * mm - 0.3413193965 * ss,
      -0.0041960863 * ll - 0.7034186147 * mm + 1.707614701 * ss,
    ]
      .map((v) => Math.max(0, Math.min(1, v)))
      .map((v) =>
        Math.round(
          255 * (v <= 0.0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - 0.055),
        ),
      )
      .map((v) => v.toString(16).padStart(2, "0"))
      .join("")
  );
}
export function luminance(hex: string): number {
  const [r, g, b] = linearRgb(hex);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrastRatio(first: string, second: string): number {
  const a = luminance(first);
  const b = luminance(second);
  return (
    (Math.max(a, b) + CONTRAST_LUMINANCE_OFFSET) /
    (Math.min(a, b) + CONTRAST_LUMINANCE_OFFSET)
  );
}
