# Changelog

## [1.2.0](https://github.com/jdx/fnox/compare/v1.1.0..v1.2.0) - 2025-10-28

### 🚀 Features

- add support for fnox.local.toml local config overrides by [@jdx](https://github.com/jdx) in [#30](https://github.com/jdx/fnox/pull/30)
- add batch secret resolution to improve performance by [@jdx](https://github.com/jdx) in [#31](https://github.com/jdx/fnox/pull/31)

### 🐛 Bug Fixes

- import command now reads from input file instead of config file by [@jdx](https://github.com/jdx) in [#28](https://github.com/jdx/fnox/pull/28)

### 📚 Documentation

- Add VitePress documentation and GitHub Pages deployment by [@jdx](https://github.com/jdx) in [#32](https://github.com/jdx/fnox/pull/32)

### 🔍 Other Changes

- Update URLs to use custom domain fnox.jdx.dev and remove DOCS_DEPLOYMENT.md by [@jdx](https://github.com/jdx) in [79a2c78](https://github.com/jdx/fnox/commit/79a2c7875e8b74283b71093be74d1e41171e5143)
- Remove DOCS_DEPLOYMENT.md by [@jdx](https://github.com/jdx) in [dd9cb7b](https://github.com/jdx/fnox/commit/dd9cb7b90c6ffff43074aaba5908cc444bb8f412)
- Remove ONEPASSWORD.md (content migrated to docs) by [@jdx](https://github.com/jdx) in [622baa3](https://github.com/jdx/fnox/commit/622baa3052abdebce3955d181848770bf9ef1ed6)
- Add fnox vault logo by [@jdx](https://github.com/jdx) in [95a100f](https://github.com/jdx/fnox/commit/95a100fd22b6c9019a5d8e0d907680a235ec52bd)
- Add auto-generated CLI reference documentation by [@jdx](https://github.com/jdx) in [582af5b](https://github.com/jdx/fnox/commit/582af5ba07f232f727041934af344bf953d72bab)
- Show CLI Reference in sidebar on all pages by [@jdx](https://github.com/jdx) in [a19d6d1](https://github.com/jdx/fnox/commit/a19d6d127ae7d462424390147e9d46643dff16a6)
- Remove 'When to Use' sections from provider docs by [@jdx](https://github.com/jdx) in [9fc9a75](https://github.com/jdx/fnox/commit/9fc9a756b9e85f5277deb46f0e11df61095eb663)
- Add custom dark theme with Fort Knox styling by [@jdx](https://github.com/jdx) in [9c83a2e](https://github.com/jdx/fnox/commit/9c83a2eb4a4e1e17bd793e6c1a6e56aecc25fac8)
- Fix dead links to /reference/commands by [@jdx](https://github.com/jdx) in [86762d8](https://github.com/jdx/fnox/commit/86762d8076f084f0fe704519dc4e2974d518dc02)

## [1.1.0](https://github.com/jdx/fnox/compare/v1.0.1..v1.1.0) - 2025-10-27

### 🚀 Features

- add top-level secret inheritance for profiles by [@jdx](https://github.com/jdx) in [#21](https://github.com/jdx/fnox/pull/21)
- add global if_missing configuration with priority chain by [@jdx](https://github.com/jdx) in [#22](https://github.com/jdx/fnox/pull/22)

### 🐛 Bug Fixes

- SSH key support in age provider by [@jdx](https://github.com/jdx) in [#26](https://github.com/jdx/fnox/pull/26)

## [1.0.1](https://github.com/jdx/fnox/compare/v1.0.0..v1.0.1) - 2025-10-26

### 🐛 Bug Fixes

- default to warn instead of error for missing secrets by [@jdx](https://github.com/jdx) in [#20](https://github.com/jdx/fnox/pull/20)
- expand tilde (~) in FNOX_AGE_KEY_FILE path by [@pepicrft](https://github.com/pepicrft) in [#17](https://github.com/jdx/fnox/pull/17)
- make the onepassword vault name optional by [@btkostner](https://github.com/btkostner) in [#15](https://github.com/jdx/fnox/pull/15)
- do not require OP_SERVICE_ACCOUNT_TOKEN for 1password by [@btkostner](https://github.com/btkostner) in [#16](https://github.com/jdx/fnox/pull/16)

### 🛡️ Security

- skip age setup and redact tests for fork PRs by [@jdx](https://github.com/jdx) in [#18](https://github.com/jdx/fnox/pull/18)

### 🔍 Other Changes

- **(ci)** add retry action for integration tests by [@jdx](https://github.com/jdx) in [#19](https://github.com/jdx/fnox/pull/19)
- **(release)** add macOS code signing to release workflow by [@jdx](https://github.com/jdx) in [#11](https://github.com/jdx/fnox/pull/11)
- wip by [@jdx](https://github.com/jdx) in [b164101](https://github.com/jdx/fnox/commit/b164101cdceac3e4c204fa5c400a48f976334a0d)
- Update README.md by [@jdx](https://github.com/jdx) in [10ac17e](https://github.com/jdx/fnox/commit/10ac17ec17a777ad9076755231229153577535b7)

### New Contributors

- @btkostner made their first contribution in [#16](https://github.com/jdx/fnox/pull/16)
- @pepicrft made their first contribution in [#17](https://github.com/jdx/fnox/pull/17)

## [1.0.0](https://github.com/jdx/fnox/compare/v0.2.2..v1.0.0) - 2025-10-20

### 🐛 Bug Fixes

- Remove duplicate openssl-sys from main dependencies by [@jdx](https://github.com/jdx) in [8b4c8c7](https://github.com/jdx/fnox/commit/8b4c8c787a0c301c6d4a4910001c7515a5c4a6a4)

## [0.2.2](https://github.com/jdx/fnox/compare/v0.2.1..v0.2.2) - 2025-10-20

### 🐛 Bug Fixes

- Clean up Azure CLI directory in test teardown by [@jdx](https://github.com/jdx) in [#5](https://github.com/jdx/fnox/pull/5)
- Make vendored OpenSSL Linux-only to fix Windows builds by [@jdx](https://github.com/jdx) in [#6](https://github.com/jdx/fnox/pull/6)

## [0.2.1](https://github.com/jdx/fnox/compare/v0.2.0..v0.2.1) - 2025-10-20

### 🐛 Bug Fixes

- Enable vendored OpenSSL for cross-compilation by [@jdx](https://github.com/jdx) in [#3](https://github.com/jdx/fnox/pull/3)

## [0.2.0](https://github.com/jdx/fnox/compare/v0.1.0..v0.2.0) - 2025-10-20

### 🚀 Features

- Add release workflow for building multi-platform binaries by [@jdx](https://github.com/jdx) in [04b63c7](https://github.com/jdx/fnox/commit/04b63c70b1a3d989cf71cca2d55d62ab5085085f)

### 🐛 Bug Fixes

- Remove label requirement from PR creation in release-plz by [@jdx](https://github.com/jdx) in [354d0a1](https://github.com/jdx/fnox/commit/354d0a17368e9051fb21fa8012356ecd83a60f35)
- Use FNOX_GH_TOKEN for PR creation permissions by [@jdx](https://github.com/jdx) in [decca13](https://github.com/jdx/fnox/commit/decca13e9a4a8e356bee8226011b1e9c868c6e5b)
- Use FNOX_GH_TOKEN in release workflow by [@jdx](https://github.com/jdx) in [64c774b](https://github.com/jdx/fnox/commit/64c774b77519602c84b20d033df10cbd468dd9d0)
- Remove incorrect [secrets] section assertions from init tests by [@jdx](https://github.com/jdx) in [7496483](https://github.com/jdx/fnox/commit/7496483a8c5bdeab615ab38616548dacfe7f4d83)

### 🔍 Other Changes

- Fix Bitwarden provider to use --session flag and close stdin by [@jdx](https://github.com/jdx) in [9dcfe86](https://github.com/jdx/fnox/commit/9dcfe86c4791c6f7cc4dcc9e5439c70a6b587c78)

### New Contributors

- @mise-en-dev made their first contribution in [#2](https://github.com/jdx/fnox/pull/2)

## [0.1.0] - 2025-10-20

### 🐛 Bug Fixes

- Handle repos with no tags in release-plz script by [@jdx](https://github.com/jdx) in [3fb62c6](https://github.com/jdx/fnox/commit/3fb62c686d32923fc182c799fc43aefd421bd071)

### 🔍 Other Changes

- init by [@jdx](https://github.com/jdx) in [8a39de2](https://github.com/jdx/fnox/commit/8a39de2e92e433eda02fda8ef686e609b7005463)

### New Contributors

- @jdx made their first contribution

<!-- generated by git-cliff -->
