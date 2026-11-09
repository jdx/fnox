const assetRoot = new URL("../assets/", import.meta.url);

const assets = {
  check: new URL("check.svg", assetRoot),
  copy: new URL("copy.svg", assetRoot),
  flow: new URL("flow.json", assetRoot),
  geometry: new URL("geometry.svg", assetRoot),
  logo: new URL("logo.svg", assetRoot),
} as const;

export const touchIdPaths = {
  assets,
  generatedHeaders: {
    animation: "fingerprint-animation.generated.h",
    detailIcons: "detail-copy-icons.generated.h",
    theme: "theme.generated.h",
  },
  iconSymbols: [
    { asset: assets.copy, symbol: "kDetailCopyIconSvg" },
    { asset: assets.check, symbol: "kDetailCheckIconSvg" },
    { asset: assets.logo, symbol: "kPreviewLogoSvg" },
  ],
} as const;
