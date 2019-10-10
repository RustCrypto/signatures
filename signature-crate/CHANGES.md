# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2019-10-10)
### Changed
- Simplify alloc gating; MSRV 1.36+ ([#28])
- Replace `DigestSignature` trait with `#[digest(...)]` attribute ([#27])
- signature_derive: Upgrade to 1.x proc macro crates ([#26])

[#28]: https://github.com/RustCrypto/signatures/pull/28
[#27]: https://github.com/RustCrypto/signatures/pull/27
[#26]: https://github.com/RustCrypto/signatures/pull/27

## 0.2.0 (2019-06-06)
### Added
- `signature_derive`: Custom derive support for `Signer`/`Verifier` ([#18])

### Changed
- Have `DigestSigner`/`DigestVerifier` take `Digest` instance ([#17])

[#18]: https://github.com/RustCrypto/signatures/pull/18
[#17]: https://github.com/RustCrypto/signatures/pull/17

## 0.1.0 (2019-05-25)

- Initial release
