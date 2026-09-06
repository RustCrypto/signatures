# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.0 (2026-06-30)
### Added
- Implement `ZeroizeOnDrop` for `SigningKey` ([#917])
- Implement `MultipartSigner/Verifier` ([#982])
- `from_components_unchecked` APIs gated under `hazmat` ([#1059])
- `TryCryptoRng` support ([#1367])
- Implement `Generate` for `Components` and `SigningKey` ([#1372])

### Changed
- Gate signing under `hazmat` feature ([#859])
- Use `crypto-primes` for key generation ([#906])
- Upgrade to the 2024 edition and bump MSRV to 1.85 ([#913])
- Make `pkcs8` feature optional ([#1014]
- Bump `rand_core` to v0.10 ([#1197])
- Bump `getrandom` to v0.4 ([#1205])
- Bump `der` to v0.8 ([#1232])
- Bump `digest` to v0.11 ([#1237])
- Bump `sha2` to v0.11 ([#1267])
- Bump `pkcs8` dependency to v0.11 ([#1316])
- Bump `signature` dependency to v3 ([#1321])
- Bump `rfc6979` to v0.6 ([#1404])

### Removed
- `std` feature ([#980])

### Security
- Migrate from known non-constant-time `num-bigint` to `crypto-bigint` as numerical library ([#906])

[#859]: https://github.com/RustCrypto/signatures/pull/859
[#906]: https://github.com/RustCrypto/signatures/pull/906
[#913]: https://github.com/RustCrypto/signatures/pull/913
[#917]: https://github.com/RustCrypto/signatures/pull/917
[#980]: https://github.com/RustCrypto/signatures/pull/980
[#982]: https://github.com/RustCrypto/signatures/pull/982
[#1014]: https://github.com/RustCrypto/signatures/pull/1014
[#1059]: https://github.com/RustCrypto/signatures/pull/1059
[#1197]: https://github.com/RustCrypto/signatures/pull/1197
[#1205]: https://github.com/RustCrypto/signatures/pull/1205
[#1232]: https://github.com/RustCrypto/signatures/pull/1232
[#1237]: https://github.com/RustCrypto/signatures/pull/1237
[#1267]: https://github.com/RustCrypto/signatures/pull/1267
[#1316]: https://github.com/RustCrypto/signatures/pull/1316
[#1321]: https://github.com/RustCrypto/signatures/pull/1321
[#1372]: https://github.com/RustCrypto/signatures/pull/1372
[#1404]: https://github.com/RustCrypto/signatures/pull/1404

## 0.6.3 (2024-01-28)
### Added
- `SigningKey::sign_prehashed_rfc6979` ([#798])

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
