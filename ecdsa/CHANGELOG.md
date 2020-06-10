# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
