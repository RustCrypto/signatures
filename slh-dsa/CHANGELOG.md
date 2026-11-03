# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (UNRELEASED)

### Added

- `pkcs8` support ([#867])
- `Zeroize` support for `SigningKey` ([#938])
- `no_std` support ([#956])
- Implement `MultipartSigner/Verifier` ([#982])

### Changed

- Upgrade to the 2024 edition; bump MSRV to 1.85 ([#913])
- Bump `zerocopy` to v0.8 ([#1071])
- Bump `rand_core` to v0.10 ([#1197])
- Bump `digest` to v0.11 ([#1263])
- Bump `sha2` to v0.11 ([#1267])
- Bump `hmac` to v0.13 ([#1274])
- Bump `pkcs8` to v0.11 ([#1316])
- Bump `signature` to v3 ([#1321])
- Migrate from `sha3` to `shake` ([#1359])

### Fixed

- PK.SEed state caching ([#1116])

[#867]: https://github.com/RustCrypto/signatures/pull/867
[#913]: https://github.com/RustCrypto/signatures/pull/913
[#938]: https://github.com/RustCrypto/signatures/pull/938
[#956]: https://github.com/RustCrypto/signatures/pull/956
[#982]: https://github.com/RustCrypto/signatures/pull/982
[#1071]: https://github.com/RustCrypto/signatures/pull/1071
[#1116]: https://github.com/RustCrypto/signatures/pull/1116
[#1197]: https://github.com/RustCrypto/signatures/pull/1197
[#1263]: https://github.com/RustCrypto/signatures/pull/1263
[#1267]: https://github.com/RustCrypto/signatures/pull/1267
[#1274]: https://github.com/RustCrypto/signatures/pull/1274
[#1316]: https://github.com/RustCrypto/signatures/pull/1316
[#1321]: https://github.com/RustCrypto/signatures/pull/1321
[#1359]: https://github.com/RustCrypto/signatures/pull/1359

## 0.1.0 (2024-08-18)
### Changed
- Implement changes from FIP 205 Initial Public Draft -> FIPS 205 Final ([#844])

### Fixed
- `no_std` support ([#845])
- Enable `derive` feature of `zerocopy` ([#847])

[#844]: https://github.com/RustCrypto/signatures/pull/844
[#845]: https://github.com/RustCrypto/signatures/pull/845
[#847]: https://github.com/RustCrypto/signatures/pull/847

## 0.0.3 (2025-05-10)
- Backport release with legacy `signature` v2 support

## 0.0.2 (2024-05-31) [YANKED]
- Initial release
