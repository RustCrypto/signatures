# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Signing uses BDS tree traversal. A signing key keeps a small state per
  layer, a signature costs a few leaf computations instead of rebuilding
  every tree from scratch. The state is not serialized: a key loaded from bytes
  rebuilds it on its first signature, at about the cost of keygen.

## 0.1.0 (2026-02-20)
- Initial release
