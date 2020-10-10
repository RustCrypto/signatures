# RustCrypto: signatures ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link]

Support for [digital signatures][1], which provide authentication of data using
public-key cryptography.

All algorithms reside in the separate crates and implemented using traits from
the [`signature`](https://docs.rs/signature/) crate.

Crates are designed so they do not require the standard library (i.e. `no_std`)
and can be easily used for bare-metal or lightweight WebAssembly programming.

## Crates

| Name        | Algorithm | Crates.io | Documentation | Build |
|-------------|-----------|-----------|---------------|-------|
| [`ecdsa`]   | [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) | [![crates.io](https://img.shields.io/crates/v/ecdsa.svg)](https://crates.io/crates/ecdsa) | [![Documentation](https://docs.rs/ecdsa/badge.svg)](https://docs.rs/ecdsa) | [![ecdsa build](https://github.com/RustCrypto/signatures/workflows/ecdsa/badge.svg?branch=master&event=push)](https://github.com/RustCrypto/signatures/actions?query=workflow%3Aecdsa) |
| [`ed25519`] | [Ed25519](https://en.wikipedia.org/wiki/EdDSA) | [![crates.io](https://img.shields.io/crates/v/ed25519.svg)](https://crates.io/crates/ed25519) | [![Documentation](https://docs.rs/ed25519/badge.svg)](https://docs.rs/ed25519) | [![ed25519 build](https://github.com/RustCrypto/signatures/workflows/ed25519/badge.svg?branch=master&event=push)](https://github.com/RustCrypto/signatures/actions?query=workflow%3Aed25519)

## Minimum Supported Rust Version

All crates in this repository support Rust **1.41** or higher. In future minimum
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

[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures

[//]: # (crates)

[`ecdsa`]: https://github.com/RustCrypto/signatures/tree/master/ecdsa
[`ed25519`]: https://github.com/RustCrypto/signatures/tree/master/ed25519

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Digital_signature
[2]: https://docs.rs/signature
