# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.1 (2026-06-05)
### Fixed
- Enable `module-lattice/alloc` when `alloc` feature is enabled ([#1365])

[#1365]: https://github.com/RustCrypto/signatures/pull/1365

## 0.1.0 (2026-05-17)
### Added
- Implement `MultipartSigner/Verifier` ([#982])
- Implement the `signature::Keypair` trait for `SigningKey` ([#1008])
- Support for external mu ([#1023], [#1074])
- Seed support i.e. `SigningKey::{from_seed, to_seed}` ([#1054], [#1094], [#1341])
- Implement `Hash` on `Signature` and `VerifyingKey` types ([#1309])
- Heap offload support for large values when `alloc` is enabled ([#1320], [#1344], [#1345])
- Implement `KeyInit`, `KeyExport`, `KeySizeUser`, and `Generate` for `SigningKey` ([#1342])

### Changed
- Bump `signature` dependency to v3 ([#954], [#1321])
- Update PKCS#8 support ([#1093])
- Rename and deprecate `ExpandedSigningKey` ([#1145])
- Use the `module-lattice` crate ([#1189])
- Use `ctutils` for constant-time selection; avoid branches ([#1245])
- Make `PartialEq` impl for `ExpandedSigningKey` constant time ([#1286])
- Bump `pkcs8` dependency to v0.11 ([#1316])
- Migrate from `sha3` to `shake` ([#1355])

### Fixed
- `no_std` support ([#989])
- Use Barrett reduction instead of integer division to prevent side-channels ([#1144])
- Wycheproof verification test failures ([#1187])
- Fix `use_hint` when 𝓇₀ = 0 ([#1194])
- Lower stack usage ([#1259], [#1261])

### Removed
- `KeyGen` trait has been removed and replaced by `KeyInit` and `Generate` ([#1349])

[#954]: https://github.com/RustCrypto/signatures/pull/954
[#982]: https://github.com/RustCrypto/signatures/pull/982
[#989]: https://github.com/RustCrypto/signatures/pull/989
[#1008]: https://github.com/RustCrypto/signatures/pull/1008
[#1023]: https://github.com/RustCrypto/signatures/pull/1023
[#1074]: https://github.com/RustCrypto/signatures/pull/1074
[#1054]: https://github.com/RustCrypto/signatures/pull/1054
[#1093]: https://github.com/RustCrypto/signatures/pull/1093
[#1094]: https://github.com/RustCrypto/signatures/pull/1094
[#1144]: https://github.com/RustCrypto/signatures/pull/1144
[#1145]: https://github.com/RustCrypto/signatures/pull/1145
[#1187]: https://github.com/RustCrypto/signatures/pull/1187
[#1189]: https://github.com/RustCrypto/signatures/pull/1189
[#1194]: https://github.com/RustCrypto/signatures/pull/1194
[#1245]: https://github.com/RustCrypto/signatures/pull/1245
[#1259]: https://github.com/RustCrypto/signatures/pull/1259
[#1261]: https://github.com/RustCrypto/signatures/pull/1261
[#1286]: https://github.com/RustCrypto/signatures/pull/1286
[#1309]: https://github.com/RustCrypto/signatures/pull/1309
[#1316]: https://github.com/RustCrypto/signatures/pull/1316
[#1320]: https://github.com/RustCrypto/signatures/pull/1320
[#1321]: https://github.com/RustCrypto/signatures/pull/1321
[#1341]: https://github.com/RustCrypto/signatures/pull/1341
[#1344]: https://github.com/RustCrypto/signatures/pull/1344
[#1342]: https://github.com/RustCrypto/signatures/pull/1342
[#1345]: https://github.com/RustCrypto/signatures/pull/1345
[#1349]: https://github.com/RustCrypto/signatures/pull/1349
[#1355]: https://github.com/RustCrypto/signatures/pull/1355

## 0.0.4 (2025-04-10)
- Initial release
