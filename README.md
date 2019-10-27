# RustCrypto: signatures

[![Build Status][build-image]][build-link]
[![Dependency Status][deps-image]][deps-link]
![Rust Version][rustc-image]

Traits which provide generic, object-safe APIs for generating and verifying
[digital signatures][1].

All algorithms reside in the separate crates and implemented using traits from
the [`signature`](https://docs.rs/signature/) crate. Additionally all crates do
not require the standard library (i.e. `no_std` capable) and can be easily used
for bare-metal or WebAssembly programming.

## Crates

| Name | Crates.io | Documentation |
| ---- | :--------:| :------------:|
| [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) | [![crates.io](https://img.shields.io/crates/v/ecdsa.svg)](https://crates.io/crates/ecdsa) | [![Documentation](https://docs.rs/ecdsa/badge.svg)](https://docs.rs/ecdsa) |
| [Ed25519](https://en.wikipedia.org/wiki/EdDSA) | [![crates.io](https://img.shields.io/crates/v/ed25519.svg)](https://crates.io/crates/ed25519) | [![Documentation](https://docs.rs/ed25519/badge.svg)](https://docs.rs/ed25519) |

## Minimum Supported Rust Version

All crates in this repository support Rust **1.34** or higher. In future minimum
supported Rust version can be changed, but it will be done with the minor
version bump.

## Usage

Crates functionality is expressed in terms of traits defined in the [`signature`][2]
crate.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[build-image]: https://travis-ci.org/RustCrypto/signatures.svg?branch=master
[build-link]: https://travis-ci.org/RustCrypto/signatures
[deps-image]: https://deps.rs/repo/github/RustCrypto/signatures/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/signatures
[rustc-image]: https://img.shields.io/badge/rustc-1.34+-blue.svg

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Digital_signature
[2]: https://docs.rs/signature
