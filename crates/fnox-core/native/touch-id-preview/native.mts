import {
  FINGERPRINT_GEOMETRY,
  FINGERPRINT_PALETTES,
  FINGERPRINT_TIMING,
  fingerprintApprovalDurationMs,
  fingerprintFrame,
  fingerprintVisitedFrames,
} from "./animation.mts";
import type { FingerprintFlow } from "./animation.mts";

export const FINGERPRINT_NATIVE_FPS = 120;

export type FingerprintRidge =
  | { kind: "arc"; start: number; end: number; clockwise: boolean }
  | { kind: "path"; commands: { kind: "M" | "C"; values: number[] }[] };

export function parseFingerprintRidges(svg: string): FingerprintRidge[] {
  const paths = Array.from(
    svg.matchAll(/<path[^>]*\bd="([^"]+)"/g),
    (match) => match[1]!,
  );
  if (paths.length !== FINGERPRINT_GEOMETRY.ridgeCount)
    throw new Error("Fingerprint requires 22 ridge paths");
  return paths.map((ridge, index) => {
    if (index < 2) {
      const values = ridge.match(/-?[0-9]*\.?[0-9]+/g)?.map(Number) ?? [];
      if (values.length < 9 || !values.every(Number.isFinite))
        throw new Error("Invalid fingerprint arc");
      const angle = (x: number, y: number) =>
        Math.atan2(
          y - FINGERPRINT_GEOMETRY.centerY,
          x - FINGERPRINT_GEOMETRY.centerX,
        );
      const rawEnd = angle(values[7]!, values[8]!);
      return {
        kind: "arc",
        start: angle(values[0]!, values[1]!),
        end: index === 1 && rawEnd > 0 ? rawEnd - 2 * Math.PI : rawEnd,
        clockwise: index === 1,
      };
    }
    const commands = Array.from(
      ridge.matchAll(/([A-Za-z])([^A-Za-z]*)/g),
      ([, command, coordinates]) => {
        const values = coordinates!.trim().split(/[ ,]+/).map(Number);
        if (
          (command !== "M" && command !== "C") ||
          values.length !== (command === "M" ? 2 : 6) ||
          !values.every(Number.isFinite)
        )
          throw new Error(`Unsupported fingerprint path command: ${command}`);
        return { kind: command as "M" | "C", values };
      },
    );
    if (commands[0]?.kind !== "M")
      throw new Error("Fingerprint path must start with a move");
    return { kind: "path", commands };
  });
}

export function fingerprintNativePaths(svg: string): string[] {
  return parseFingerprintRidges(svg).map((ridge) => {
    if (ridge.kind === "arc")
      return `CGPathAddArc(p,nullptr,${FINGERPRINT_GEOMETRY.centerX},${FINGERPRINT_GEOMETRY.centerY},${FINGERPRINT_GEOMETRY.radius},${ridge.start},${ridge.end},${ridge.clockwise});`;
    return ridge.commands
      .map((command) =>
        command.kind === "M"
          ? `CGPathMoveToPoint(p,nullptr,${command.values.join(",")});`
          : `CGPathAddCurveToPoint(p,nullptr,${command.values.join(",")});`,
      )
      .join("\n");
  });
}

export function fingerprintNativeSamples(flow: FingerprintFlow) {
  if (
    flow.frames.length !== FINGERPRINT_GEOMETRY.ridgeCount ||
    flow.directions.length !== FINGERPRINT_GEOMETRY.ridgeCount
  )
    throw new Error("Fingerprint flow must describe all 22 ridges");
  const visited = flow.frames.map(fingerprintVisitedFrames);
  const count =
    Math.round(
      (FINGERPRINT_TIMING.durationMs / 1000) * FINGERPRINT_NATIVE_FPS,
    ) + 1;
  return [FINGERPRINT_PALETTES.light, FINGERPRINT_PALETTES.dark].map(
    (palette) =>
      Array.from({ length: count }, (_, index) =>
        fingerprintFrame(
          (index * 1000) / FINGERPRINT_NATIVE_FPS,
          flow,
          visited,
          palette,
        ),
      ),
  );
}

export function createFingerprintNativeHeader(
  svg: string,
  flow: FingerprintFlow,
): string {
  const paths = fingerprintNativePaths(svg);
  const samples = fingerprintNativeSamples(flow);
  const count = samples[0]!.length;
  const number = (value: number) => Number(value.toFixed(7)).toString();
  const array = (values: readonly number[]) =>
    `{${values.map(number).join(",")}}`;
  const color = (value: string) => `0x${value.slice(1)}`;
  const tables = samples.map((frames) =>
    frames
      .map((frame) => {
        return `{${array(frame.extents)},${array(frame.visited)},{${frame.activeColors.map(color).join(",")}},{${frame.tones.map(color).join(",")}},${color(frame.pale)},${color(frame.ringColor)},${color(frame.checkColor)},${number(frame.progress)},${number(frame.eased)},${number(frame.ringSpan)},${number(frame.checkOpacity)},${array(frame.checkEnd)}}`;
      })
      .join(",\n"),
  );
  return `#pragma once
#include <cstdint>
constexpr unsigned kFingerprintRidgeCount=${paths.length};
constexpr unsigned kFingerprintSampleCount=${count};
constexpr double kFingerprintSampleRate=${FINGERPRINT_NATIVE_FPS};
constexpr double kFingerprintApprovalDuration=${fingerprintApprovalDurationMs() / 1000};
constexpr double kFingerprintReducedMotionDuration=${fingerprintApprovalDurationMs(true) / 1000};
constexpr double kFingerprintStrokeWidth=${FINGERPRINT_GEOMETRY.strokeWidth};
constexpr double kFingerprintCenterX=${FINGERPRINT_GEOMETRY.centerX};
constexpr double kFingerprintCenterY=${FINGERPRINT_GEOMETRY.centerY};
constexpr double kFingerprintRadius=${FINGERPRINT_GEOMETRY.radius};
constexpr bool kFingerprintFromEnd[]={${flow.directions.join(",")}};
struct FingerprintSample {
 double extents[kFingerprintRidgeCount], visited[kFingerprintRidgeCount];
 uint32_t active[kFingerprintRidgeCount], tones[3], pale, ring, check;
 double progress, eased, span, checkOpacity, checkEnd[2];
};
constexpr FingerprintSample kFingerprintSamples[2][kFingerprintSampleCount]={
{${tables[0]}},
{${tables[1]}}
};
inline CGPathRef CreateFingerprintRidge(unsigned index, const CGAffineTransform* transform) {
 CGMutablePathRef p=CGPathCreateMutable();
 switch(index){${paths.map((commands, index) => `case ${index}: ${commands} break;`).join("\n")}}
 CGPathRef result=CGPathCreateCopyByTransformingPath(p,transform);
 CGPathRelease(p);
 return result;
}
`;
}
