# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.3 (2024-01-28)
### Added
- `SigningKey::sign_prehashed_rfc6979 ([#798])

[#798]: https://github.com/RustCrypto/signatures/pull/798

## 0.6.2 (2023-11-16)
### Changed
- Loosen `signature` bound to `2.0, <2.3` ([#756])

[#756]: https://github.com/RustCrypto/signatures/pull/756

## 0.6.1 (2023-04-04)
### Changed
- Loosen `signature` bound to `2.0, <2.2` ([#697])

[#697]: https://github.com/RustCrypto/signatures/pull/697

## 0.6.0 (2023-03-01)
### Changed
- Bump `rfc6979` dependency to v0.4 ([#662])
- Bump `pkcs8` dependency to v0.10; MSRV 1.65 ([#664])

[#662]: https://github.com/RustCrypto/signatures/pull/662
[#664]: https://github.com/RustCrypto/signatures/pull/664

## 0.5.0 (2023-01-15)
### Changed
- Use `&mut impl CryptoRngCore` ([#579])
- Bump `signature` crate dependency to v2.0 ([#614])

### Removed
- Use of `opaque-debug` ([#572])

[#572]: https://github.com/RustCrypto/signatures/pull/572
[#579]: https://github.com/RustCrypto/signatures/pull/579
[#614]: https://github.com/RustCrypto/signatures/pull/614

## 0.4.2 (2022-10-29)
### Added
- Expose signing and verifying of prehashed hash value ([#558])
- Implement `Signer` and `Verifier` using SHA-256 as default ([#559])

[#558]: https://github.com/RustCrypto/signatures/pull/558
[#559]: https://github.com/RustCrypto/signatures/pull/559

## 0.4.1 (2022-10-11)
### Added
- Re-export `BigUint` ([#553])

[#553]: https://github.com/RustCrypto/signatures/pull/553

## 0.4.0 (2022-08-15)
### Changed
- Bump `rfc6979` to v0.3 ([#500])
- Allow `signature` v1.6 ([#513])

[#500]: https://github.com/RustCrypto/signatures/pull/500
[#513]: https://github.com/RustCrypto/signatures/pull/513

## 0.3.0 (2022-05-21)
### Added
- Internal sanity check validating the `r` and `s` components of the signature ([#489])
- Public `OID` constant representing the object identifier defined in RFC3279 § 2.3.2 ([#489]) 

### Changed
- `Components::generate` now takes an `KeySize` struct instead of an `(u32, u3e2)` tuple ([#489])
- `Components::from_components`, `SigningKey::from_components` and `VerifyingKey::from_components`
  are now fallible and validate themselves upon creation ([#489])

### Removed
- `is_valid` methods on `Components`, `SigningKey` and `VerifyingKey`: constructor now ensures that
  invalid forms are unrepresentable ([#489])

[#489]: https://github.com/RustCrypto/signatures/pull/489

## 0.2.0 (2022-05-16)
- Initial RustCrypto crate release

## 0.1.0 (2018-07-13)
- Pre-RustCrypto release
