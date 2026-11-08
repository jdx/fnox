import { DARK_THEME, LIGHT_THEME } from "./theme.mts";
export const FINGERPRINT_TIMING = Object.freeze({
  durationMs: 4200,
  referenceStartSeconds: 83.8,
  circleStartMs: 2450,
  circleDurationMs: 320,
  successDurationMs: 440,
  completionHoldMs: 150,
  reducedMotionHoldMs: 180,
});

export function fingerprintApprovalDurationMs(reduceMotion = false): number {
  if (reduceMotion) return FINGERPRINT_TIMING.reducedMotionHoldMs;
  return (
    FINGERPRINT_TIMING.circleStartMs +
    Math.max(
      FINGERPRINT_TIMING.circleDurationMs,
      FINGERPRINT_TIMING.successDurationMs,
    ) +
    FINGERPRINT_TIMING.completionHoldMs
  );
}

export const FINGERPRINT_GEOMETRY = Object.freeze({
  centerX: 144.03181808145024,
  centerY: 143.8459782226648,
  radius: 124.95128984742918,
  ridgeCount: 22,
  strokeWidth: 5.7,
});

export const FINGERPRINT_GRAY_FADE_VISITED = 0.72;
export const FINGERPRINT_FALLBACK_PALE_MIX = 0.66;

export const fingerprintPalette = (
  theme: typeof DARK_THEME | typeof LIGHT_THEME,
) => [theme.resting, theme.incoming, theme.success, theme.check, theme.trail];
export const FINGERPRINT_PALETTES = Object.freeze({
  light: fingerprintPalette(LIGHT_THEME),
  dark: fingerprintPalette(DARK_THEME),
});

export interface FingerprintFlow {
  start: number;
  fps: number;
  directions: boolean[];
  frames: number[][];
}

export function fingerprintFrame(
  milliseconds: number,
  flow: FingerprintFlow,
  visitedFrames: ReadonlyArray<readonly number[]>,
  palette: readonly string[],
) {
  const position =
    (FINGERPRINT_TIMING.referenceStartSeconds +
      milliseconds / 1000 -
      flow.start) *
    flow.fps;
  const extents = flow.frames.map((samples) =>
    sampleFingerprintFlow(samples, position),
  );
  const visited = visitedFrames.map((samples) =>
    sampleFingerprintFlow(samples, position, true),
  );
  const progress = clampFingerprintProgress(
    (milliseconds - FINGERPRINT_TIMING.circleStartMs) /
      FINGERPRINT_TIMING.successDurationMs,
  );
  const eased = easeFingerprintProgress(progress);
  const {
    0: idle,
    1: active,
    2: success,
    3: check,
    4: paleColor,
  } = palette as [string, string, string, string, string?];
  const pale =
    paleColor ??
    mixFingerprintColor(active, "#ffffff", FINGERPRINT_FALLBACK_PALE_MIX);
  // Only the visited paths gain color; untouched ridges retain the resting fill.
  const base = idle;
  return {
    __proto__: null,
    extents,
    visited,
    progress,
    eased,
    pale,
    tones: [base, base, base],
    activeColors: extents.map(() => active),
    ringColor: success,
    ringSpan: fingerprintCircleSpan(milliseconds),
    checkColor: check,
    checkOpacity: easeFingerprintProgress(
      clampFingerprintProgress((progress - 0.08) / 0.65),
    ),
    checkEnd: [152 + 40 * progress ** 1.4, 150 - 51 * progress ** 1.4],
  };
}

export function clampFingerprintProgress(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0;
}

export function easeFingerprintProgress(value: number): number {
  const progress = clampFingerprintProgress(value);
  return progress * progress * (3 - 2 * progress);
}

export function mixFingerprintColor(
  first: string,
  second: string,
  value: number,
): string {
  const progress = clampFingerprintProgress(value);
  const firstChannels = parseFingerprintColor(first);
  const secondChannels = parseFingerprintColor(second);
  return (
    "#" +
    firstChannels
      .map((channel, index) =>
        Math.round(channel + (secondChannels[index]! - channel) * progress)
          .toString(16)
          .padStart(2, "0"),
      )
      .join("")
  );
}

export function parseFingerprintColor(color: string): number[] {
  if (!/^#[a-f0-9]{6}$/i.test(color)) {
    throw new TypeError("Expected a six-digit fingerprint color");
  }
  return color
    .slice(1)
    .match(/.{2}/g)!
    .map((channel) => Number.parseInt(channel, 16));
}

export function fingerprintColorLuminance(color: string): number {
  const channels = parseFingerprintColor(color).map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return channels[0]! * 0.2126 + channels[1]! * 0.7152 + channels[2]! * 0.0722;
}

export function neutralFingerprintColor(color: string): string {
  const luminance = fingerprintColorLuminance(color);
  const encoded =
    luminance <= 0.0031308
      ? 12.92 * luminance
      : 1.055 * luminance ** (1 / 2.4) - 0.055;
  const channel = Math.round(encoded * 255)
    .toString(16)
    .padStart(2, "0");
  return "#" + channel.repeat(3);
}

export function sampleFingerprintFlow(
  samples: readonly number[],
  position: number,
  hold = false,
): number {
  if (!Number.isFinite(position) || position < 0 || samples.length === 0) {
    return 0;
  }
  if (position > samples.length - 1) {
    return hold ? samples.at(-1)! : 0;
  }
  const index = Math.floor(position);
  const first = samples[index]!;
  return first + ((samples[index + 1] ?? first) - first) * (position - index);
}

export function fingerprintVisitedFrames(samples: readonly number[]): number[] {
  let peak = 0;
  return samples.map((value) => (peak = Math.max(peak, value)));
}

export function fingerprintDash(
  extent: number,
  { fromEnd }: { fromEnd: boolean },
): { length: number; offset: number } {
  const length = 100 * clampFingerprintProgress(extent);
  return { length, offset: fromEnd ? length - 100 : 0 };
}

export function fingerprintCircleSpan(milliseconds: number): number {
  const progress = clampFingerprintProgress(
    (milliseconds - FINGERPRINT_TIMING.circleStartMs) /
      FINGERPRINT_TIMING.circleDurationMs,
  );
  return 2 * Math.PI * Math.sin((progress * Math.PI) / 2);
}
