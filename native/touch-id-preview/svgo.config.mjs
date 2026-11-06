// The animation indexes 22 ridges and parses absolute M/C commands (plus its
// first two arc paths). Preserve path data, order, and numeric precision.
export default {
  multipass: true,
  plugins: [
    {
      name: "preset-default",
      params: {
        overrides: {
          convertPathData: false,
          mergePaths: false,
          cleanupNumericValues: false,
          moveElemsAttrsToGroup: false,
          moveGroupAttrsToElems: false,
          collapseGroups: false,
        },
      },
    },
  ],
};
