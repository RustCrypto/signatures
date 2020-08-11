# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.1 (2020-08-10)
### Changed
- Use `all-features = true` on docs.rs ([#126])

[#126]: https://github.com/RustCrypto/signatures/pull/126

## 0.7.0 (2020-08-10)
### Added
- `hazmat` traits: `SignPrimitive`, `RecoverableSignPrimitive`,
  `VerifyPrimitive`, `DigestPrimitive` ([#96], [#99], [#107], [#111])
- `dev` module ([#103])
- `NormalizeLow` trait ([#115], [#118], [#119])
- `Copy` impl on `Signature` ([#117])
- `RecoverableSignPrimitive` ([#120])

### Changed
- Bumped `elliptic-curve` crate to v0.5 release ([#123])
- Renamed `FixedSignature` to `ecdsa::Signature` ([#98])
- Renamed `Asn1Signature` to `ecdsa::asn1::Signature` ([#98], [#102])

### Removed
- Curve-specific types - migrated to `k256`, `p256`, `p384` crates ([#96])

[#96]: https://github.com/RustCrypto/signatures/pull/96
[#98]: https://github.com/RustCrypto/signatures/pull/98
[#99]: https://github.com/RustCrypto/signatures/pull/99
[#102]: https://github.com/RustCrypto/signatures/pull/102
[#103]: https://github.com/RustCrypto/signatures/pull/103
[#107]: https://github.com/RustCrypto/signatures/pull/107
[#111]: https://github.com/RustCrypto/signatures/pull/111
[#115]: https://github.com/RustCrypto/signatures/pull/115
[#117]: https://github.com/RustCrypto/signatures/pull/117
[#118]: https://github.com/RustCrypto/signatures/pull/118
[#119]: https://github.com/RustCrypto/signatures/pull/119
[#120]: https://github.com/RustCrypto/signatures/pull/120
[#123]: https://github.com/RustCrypto/signatures/pull/123

## 0.6.1 (2020-06-29)
### Added
- `doc_cfg` attributes for https://docs.rs ([#91])
- `ecdsa::curve::secp256k1::RecoverableSignature` ([#90])

[#91]: https://github.com/RustCrypto/signatures/pull/91
[#90]: https://github.com/RustCrypto/signatures/pull/90

## 0.6.0 (2020-06-09)
### Changed
- Upgrade to `signature` ~1.1.0; `sha` v0.9 ([#87])
- Bump all elliptic curve crates; MSRV 1.41+ ([#86])

[#87]: https://github.com/RustCrypto/signatures/pull/87
[#86]: https://github.com/RustCrypto/signatures/pull/86

## 0.5.0 (2020-04-18)
### Changed
- Upgrade `signature` crate to v1.0 final release ([#80])

[#80]: https://github.com/RustCrypto/signatures/pull/80

## 0.4.0 (2020-01-07)
### Changed
- Upgrade `elliptic-curve` crate to v0.3.0; make curves cargo features ([#68])

[#68]: https://github.com/RustCrypto/signatures/pull/68

## 0.3.0 (2019-12-11)
### Changed
- Upgrade `elliptic-curve` crate to v0.2.0; MSRV 1.37+ ([#65])

[#65]: https://github.com/RustCrypto/signatures/pull/65

## 0.2.1 (2019-12-06)
### Added
- Re-export `PublicKey` and `SecretKey` from the `elliptic-curve` crate ([#61])

[#61]: https://github.com/RustCrypto/signatures/pull/61

## 0.2.0 (2019-12-06)
### Changed
- Use curve types from the `elliptic-curve` crate ([#58])

[#58]: https://github.com/RustCrypto/signatures/pull/58

## 0.1.0 (2019-10-29)

- Initial release
