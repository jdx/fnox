# Changelog

## [1.9.2](https://github.com/jdx/fnox/compare/v1.9.1..v1.9.2) - 2026-01-19

### 🐛 Bug Fixes

- gen-release-notes improvements by [@jdx](https://github.com/jdx) in [#191](https://github.com/jdx/fnox/pull/191)

### 🔍 Other Changes

- exclude CHANGELOG.md from prettier by [@jdx](https://github.com/jdx) in [#190](https://github.com/jdx/fnox/pull/190)

## [1.9.1](https://github.com/jdx/fnox/compare/v1.9.0..v1.9.1) - 2026-01-19

### 🐛 Bug Fixes

- use positional args in gen-release-notes by [@jdx](https://github.com/jdx) in [#187](https://github.com/jdx/fnox/pull/187)

## [1.9.0](https://github.com/jdx/fnox/compare/v1.8.0..v1.9.0) - 2026-01-19

### 🚀 Features

- add authentication prompting for expired credentials by [@jdx](https://github.com/jdx) in [#184](https://github.com/jdx/fnox/pull/184)
- add LLM-generated editorialized release notes by [@jdx](https://github.com/jdx) in [#185](https://github.com/jdx/fnox/pull/185)

### 🐛 Bug Fixes

- remove LLM generation from release-plz by [@jdx](https://github.com/jdx) in [#186](https://github.com/jdx/fnox/pull/186)

### 🚜 Refactor

- **(edit)** batch resolve secrets by profile for efficiency by [@johnpyp](https://github.com/johnpyp) in [#182](https://github.com/jdx/fnox/pull/182)

## [1.8.0](https://github.com/jdx/fnox/compare/v1.7.0..v1.8.0) - 2026-01-17

### 🚀 Features

- add passwordstate provider by [@davidolrik](https://github.com/davidolrik) in [#147](https://github.com/jdx/fnox/pull/147)
- aws-ps batch concurrency, aws-kms 10 -> 100 concurrency by [@johnpyp](https://github.com/johnpyp) in [#180](https://github.com/jdx/fnox/pull/180)

### 🐛 Bug Fixes

- resolve clippy unused_assignments warnings in error.rs by [@jdx](https://github.com/jdx) in [#174](https://github.com/jdx/fnox/pull/174)
- improve AWS SDK error messages and enable SSO support by [@daghoidahl](https://github.com/daghoidahl) in [#173](https://github.com/jdx/fnox/pull/173)

### 📚 Documentation

- add AWS Parameter store to sidebar and provider lists by [@johnpyp](https://github.com/johnpyp) in [#178](https://github.com/jdx/fnox/pull/178)

### 🧪 Testing

- Add missing skip logic to aws_parameter_store.bats by [@jdx](https://github.com/jdx) in [#145](https://github.com/jdx/fnox/pull/145)

### 🛡️ Security

- **(deps)** update azure-sdk-for-rust monorepo to 0.30 by [@renovate[bot]](https://github.com/renovate[bot]) in [#144](https://github.com/jdx/fnox/pull/144)

### 📦️ Dependency Updates

- pin dependencies by [@renovate[bot]](https://github.com/renovate[bot]) in [#133](https://github.com/jdx/fnox/pull/133)
- update rust crate demand to v1.8.0 by [@renovate[bot]](https://github.com/renovate[bot]) in [#134](https://github.com/jdx/fnox/pull/134)
- lock file maintenance by [@renovate[bot]](https://github.com/renovate[bot]) in [#137](https://github.com/jdx/fnox/pull/137)
- update rust crate usage-lib to v2.9.0 by [@renovate[bot]](https://github.com/renovate[bot]) in [#143](https://github.com/jdx/fnox/pull/143)
- update rust crate age to v0.11.2 by [@renovate[bot]](https://github.com/renovate[bot]) in [#149](https://github.com/jdx/fnox/pull/149)
- update aws-sdk-rust monorepo to v1.8.12 by [@renovate[bot]](https://github.com/renovate[bot]) in [#148](https://github.com/jdx/fnox/pull/148)
- update rust crate gcp_auth to v0.12.5 by [@renovate[bot]](https://github.com/renovate[bot]) in [#151](https://github.com/jdx/fnox/pull/151)
- update rust crate dbus to v0.9.10 by [@renovate[bot]](https://github.com/renovate[bot]) in [#150](https://github.com/jdx/fnox/pull/150)
- update rust crate google-cloud-secretmanager-v1 to v1.2.0 by [@renovate[bot]](https://github.com/renovate[bot]) in [#153](https://github.com/jdx/fnox/pull/153)
- update rust crate reqwest to v0.12.25 by [@renovate[bot]](https://github.com/renovate[bot]) in [#152](https://github.com/jdx/fnox/pull/152)
- lock file maintenance by [@renovate[bot]](https://github.com/renovate[bot]) in [#154](https://github.com/jdx/fnox/pull/154)
- update dependency vue to v3.5.26 by [@renovate[bot]](https://github.com/renovate[bot]) in [#156](https://github.com/jdx/fnox/pull/156)
- update rust crate console to v0.16.2 by [@renovate[bot]](https://github.com/renovate[bot]) in [#157](https://github.com/jdx/fnox/pull/157)
- lock file maintenance by [@renovate[bot]](https://github.com/renovate[bot]) in [#162](https://github.com/jdx/fnox/pull/162)
- update rust crate arc-swap to v1.8.0 by [@renovate[bot]](https://github.com/renovate[bot]) in [#167](https://github.com/jdx/fnox/pull/167)
- update rust crate chrono to v0.4.43 by [@renovate[bot]](https://github.com/renovate[bot]) in [#176](https://github.com/jdx/fnox/pull/176)
- update aws-sdk-rust monorepo to v1.98.0 by [@renovate[bot]](https://github.com/renovate[bot]) in [#177](https://github.com/jdx/fnox/pull/177)

### New Contributors

- @johnpyp made their first contribution in [#180](https://github.com/jdx/fnox/pull/180)
- @daghoidahl made their first contribution in [#173](https://github.com/jdx/fnox/pull/173)
- @davidolrik made their first contribution in [#147](https://github.com/jdx/fnox/pull/147)

## [1.7.0](https://github.com/jdx/fnox/compare/v1.6.1..v1.7.0) - 2025-11-27

### 🚀 Features

- **(init)** improve wizard with traits and missing providers by [@jdx](https://github.com/jdx) in [#129](https://github.com/jdx/fnox/pull/129)
- add KeePass provider support by [@jdx](https://github.com/jdx) in [#123](https://github.com/jdx/fnox/pull/123)
- add AWS Parameter Store provider support by [@jdx](https://github.com/jdx) in [#126](https://github.com/jdx/fnox/pull/126)
- support global config file for machine-wide secrets by [@jdx](https://github.com/jdx) in [#128](https://github.com/jdx/fnox/pull/128)
- add secret references in provider configuration by [@jdx](https://github.com/jdx) in [#131](https://github.com/jdx/fnox/pull/131)

### 🐛 Bug Fixes

- **(set)** always write to local config, create override for parent secrets by [@jdx](https://github.com/jdx) in [#122](https://github.com/jdx/fnox/pull/122)

### 🚜 Refactor

- simplify Provider trait by removing key_file parameter by [@jdx](https://github.com/jdx) in [#124](https://github.com/jdx/fnox/pull/124)

### 📚 Documentation

- add KeePass provider documentation by [@jdx](https://github.com/jdx) in [#125](https://github.com/jdx/fnox/pull/125)

### ⚡ Performance

- **(tests)** reduce AWS Secrets Manager API calls by [@jdx](https://github.com/jdx) in [#127](https://github.com/jdx/fnox/pull/127)

## [1.6.1](https://github.com/jdx/fnox/compare/v1.6.0..v1.6.1) - 2025-11-26

### 🐛 Bug Fixes

- **(edit)** preserve all user edits including non-secret config by [@jdx](https://github.com/jdx) in [#119](https://github.com/jdx/fnox/pull/119)

### 🚜 Refactor

- **(age)** use age crate for encryption instead of CLI by [@KokaKiwi](https://github.com/KokaKiwi) in [#112](https://github.com/jdx/fnox/pull/112)
- **(password-store)** implement Provider trait with put_secret returning key by [@KokaKiwi](https://github.com/KokaKiwi) in [#117](https://github.com/jdx/fnox/pull/117)

### 📚 Documentation

- add password-store provider documentation by [@KokaKiwi](https://github.com/KokaKiwi) in [#111](https://github.com/jdx/fnox/pull/111)

### 📦️ Dependency Updates

- lock file maintenance by [@renovate[bot]](https://github.com/renovate[bot]) in [#113](https://github.com/jdx/fnox/pull/113)
- lock file maintenance by [@renovate[bot]](https://github.com/renovate[bot]) in [#114](https://github.com/jdx/fnox/pull/114)

### New Contributors

- @renovate[bot] made their first contribution in [#114](https://github.com/jdx/fnox/pull/114)

## [1.6.0](https://github.com/jdx/fnox/compare/v1.5.2..v1.6.0) - 2025-11-21

### 🚀 Features

- add password-store provider with GPG-encrypted local storage by [@KokaKiwi](https://github.com/KokaKiwi) in [#102](https://github.com/jdx/fnox/pull/102)

### 🐛 Bug Fixes

- prevent config hierarchy duplication in fnox set command by [@jdx](https://github.com/jdx) in [#107](https://github.com/jdx/fnox/pull/107)
- preserve newly created profile sections in edit command by [@jdx](https://github.com/jdx) in [#108](https://github.com/jdx/fnox/pull/108)

### 📚 Documentation

- add looping example for age provider by [@Lailanater](https://github.com/Lailanater) in [#106](https://github.com/jdx/fnox/pull/106)

### New Contributors

- @Lailanater made their first contribution in [#106](https://github.com/jdx/fnox/pull/106)
- @KokaKiwi made their first contribution in [#102](https://github.com/jdx/fnox/pull/102)

## [1.5.2](https://github.com/jdx/fnox/compare/v1.5.1..v1.5.2) - 2025-11-19

### 🐛 Bug Fixes

- **(ci)** vendor dbus dependency for cross-compilation by [@jdx](https://github.com/jdx) in [#99](https://github.com/jdx/fnox/pull/99)

## [1.5.1](https://github.com/jdx/fnox/compare/v1.5.0..v1.5.1) - 2025-11-18

### 🐛 Bug Fixes

- **(ci)** configure dbus dependencies for cross-compilation by [@jdx](https://github.com/jdx) in [#97](https://github.com/jdx/fnox/pull/97)

## [1.5.0](https://github.com/jdx/fnox/compare/v1.4.0..v1.5.0) - 2025-11-18

### 🚀 Features

- **(bitwarden)** rbw support (experimental) by [@nilleb](https://github.com/nilleb) in [#91](https://github.com/jdx/fnox/pull/91)

### 🐛 Bug Fixes

- **(ci)** bitwarden setup by [@nilleb](https://github.com/nilleb) in [#92](https://github.com/jdx/fnox/pull/92)
- **(ci)** install dbus dependencies for release workflow by [@jdx](https://github.com/jdx) in [#96](https://github.com/jdx/fnox/pull/96)

## [1.4.0](https://github.com/jdx/fnox/compare/v1.3.0..v1.4.0) - 2025-11-15

### 🚀 Features

- **(bitwarden)** specify profile by [@nilleb](https://github.com/nilleb) in [#90](https://github.com/jdx/fnox/pull/90)

### 🐛 Bug Fixes

- **(ci)** make final job fail if any dependencies fail by [@jdx](https://github.com/jdx) in [#74](https://github.com/jdx/fnox/pull/74)
- **(ci)** install dbus dependencies for autofix and release-plz workflows by [@jdx](https://github.com/jdx) in [#89](https://github.com/jdx/fnox/pull/89)
- **(docs)** imports -> import by [@lttb](https://github.com/lttb) in [#84](https://github.com/jdx/fnox/pull/84)
- **(edit)** add .toml extension, decrypt secrets properly, and support adding new secrets by [@jdx](https://github.com/jdx) in [#88](https://github.com/jdx/fnox/pull/88)
- **(keychain)** use Secret Service backend for Linux by [@jdx](https://github.com/jdx) in [#86](https://github.com/jdx/fnox/pull/86)
- respect --profile/-P CLI flag when loading config files by [@jdx](https://github.com/jdx) in [#87](https://github.com/jdx/fnox/pull/87)

### 🔍 Other Changes

- shellcheck/shfmt by [@jdx](https://github.com/jdx) in [#77](https://github.com/jdx/fnox/pull/77)

### New Contributors

- @nilleb made their first contribution in [#90](https://github.com/jdx/fnox/pull/90)
- @lttb made their first contribution in [#84](https://github.com/jdx/fnox/pull/84)

## [1.3.0](https://github.com/jdx/fnox/compare/v1.2.3..v1.3.0) - 2025-11-01

### 🚀 Features

- add support for fnox.$FNOX_PROFILE.toml config files by [@jdx](https://github.com/jdx) in [#64](https://github.com/jdx/fnox/pull/64)
- add Infisical provider with CLI integration and self-hosted CI by [@jdx](https://github.com/jdx) in [#67](https://github.com/jdx/fnox/pull/67)

### 🐛 Bug Fixes

- **(tests)** skip keychain tests in CI when gnome-keyring-daemon unavailable by [@jdx](https://github.com/jdx) in [#72](https://github.com/jdx/fnox/pull/72)
- **(tests)** let gnome-keyring-daemon create its own control directory by [@jdx](https://github.com/jdx) in [#73](https://github.com/jdx/fnox/pull/73)
- add unique namespacing to parallel provider tests by [@jdx](https://github.com/jdx) in [#68](https://github.com/jdx/fnox/pull/68)

### 🚜 Refactor

- remove unused env_diff module and __FNOX_DIFF by [@jdx](https://github.com/jdx) in [#70](https://github.com/jdx/fnox/pull/70)

### ⚡ Performance

- parallelize CI tests across GHA workers using tranches by [@jdx](https://github.com/jdx) in [#65](https://github.com/jdx/fnox/pull/65)

### 🛡️ Security

- **(security)** store only hashes in __FNOX_SESSION instead of plaintext secrets by [@jdx](https://github.com/jdx) in [#71](https://github.com/jdx/fnox/pull/71)

## [1.2.3](https://github.com/jdx/fnox/compare/v1.2.2..v1.2.3) - 2025-11-01

### 🐛 Bug Fixes

- support FNOX_AGE_KEY by [@Cantido](https://github.com/Cantido) in [#60](https://github.com/jdx/fnox/pull/60)
- use inline tables by default in TOML output and preserve existing format by [@jdx](https://github.com/jdx) in [#62](https://github.com/jdx/fnox/pull/62)
- enhance edit command to decrypt secrets before editing by [@jdx](https://github.com/jdx) in [#63](https://github.com/jdx/fnox/pull/63)

### 📚 Documentation

- use single-line TOML syntax with section headers by [@jdx](https://github.com/jdx) in [#51](https://github.com/jdx/fnox/pull/51)
- clean up documentation and organize providers sidebar by [@jdx](https://github.com/jdx) in [cd019c0](https://github.com/jdx/fnox/commit/cd019c00a77370790444d85d4bc80d25f63ceacc)

### 🛡️ Security

- warn about multiline secrets in ci-redact by [@jdx](https://github.com/jdx) in [#53](https://github.com/jdx/fnox/pull/53)

### 🔍 Other Changes

- add semantic PR title validation by [@jdx](https://github.com/jdx) in [#61](https://github.com/jdx/fnox/pull/61)

### New Contributors

- @Cantido made their first contribution in [#60](https://github.com/jdx/fnox/pull/60)

## [1.2.2](https://github.com/jdx/fnox/compare/v1.2.1..v1.2.2) - 2025-10-29

### 🐛 Bug Fixes

- resolve secrets from providers when using --values flag in list command by [@jdx](https://github.com/jdx) in [#47](https://github.com/jdx/fnox/pull/47)
- hook-env now inherits providers from parent configs by [@jdx](https://github.com/jdx) in [#37](https://github.com/jdx/fnox/pull/37)

### 🚜 Refactor

- change profile flag from -p to -P by [@jdx](https://github.com/jdx) in [#42](https://github.com/jdx/fnox/pull/42)

### 📚 Documentation

- clean up local overrides docs by [@jdx](https://github.com/jdx) in [#46](https://github.com/jdx/fnox/pull/46)

### 🔍 Other Changes

- Update commands reference link to CLI reference by [@thomascjohnson](https://github.com/thomascjohnson) in [#44](https://github.com/jdx/fnox/pull/44)
- add autofix.ci workflow for automatic linting fixes by [@jdx](https://github.com/jdx) in [#45](https://github.com/jdx/fnox/pull/45)

### New Contributors

- @thomascjohnson made their first contribution in [#44](https://github.com/jdx/fnox/pull/44)

## [1.2.1](https://github.com/jdx/fnox/compare/v1.2.0..v1.2.1) - 2025-10-28

### 🛡️ Security

- **(import)** require --provider flag to prevent plaintext storage by [@jdx](https://github.com/jdx) in [#35](https://github.com/jdx/fnox/pull/35)

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
