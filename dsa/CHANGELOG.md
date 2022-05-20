# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Internal sanity check validating the `r` and `s` components of the signature

### Changed

- `Components::generate` now takes an `KeySize` struct instead of an `(u32, u32)` tuple
- `Components::from_components`, `SigningKey::from_components` and `VerifyingKey::from_components` are now fallible and validate themselves upon creation

### Removed

- `is_valid` functions on `Components`, `SigningKey` and `VerifyingKey` (successful construction/deserialisation now implies validity)

## 0.2.0 (2022-05-16)
- Initial release
