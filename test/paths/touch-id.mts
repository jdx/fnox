export * from "../../crates/fnox-core/native/touch-id/animation.mts";
export * from "../../crates/fnox-core/native/touch-id/build-header.mts";
export * from "../../crates/fnox-core/native/touch-id/color.mts";
export * from "../../crates/fnox-core/native/touch-id/native.mts";
export { default as svgoConfig } from "../../crates/fnox-core/native/touch-id/svgo.config.mjs";
export * from "../../crates/fnox-core/native/touch-id/theme.mts";

const touchIdRoot = new URL(
  "../../crates/fnox-core/native/touch-id/",
  import.meta.url,
);

export const touchIdPaths = {
  approvalPrompt: new URL("src/approval-prompt.mm", touchIdRoot),
  assets: {
    flow: new URL("assets/flow.json", touchIdRoot),
    geometry: new URL("assets/geometry.svg", touchIdRoot),
  },
  buildHeader: new URL("build-header.mts", touchIdRoot),
  preview: {
    nodeVersionCheck: new URL("preview/node-version-check.cmake", touchIdRoot),
    signApp: new URL("preview/sign-app.sh", touchIdRoot),
  },
} as const;
