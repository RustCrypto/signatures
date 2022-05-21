# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
