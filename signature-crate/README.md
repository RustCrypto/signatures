# `signature` crate

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

This crate contains traits which provide generic, object-safe APIs for
generating and verifying [digital signatures][1].

It's presently useful in conjunction with the [`ed25519`][2] crate.
Support is also planned for the [`ecdsa`][3] and [`rsa`][4] crates.

[Documentation][docs-link]

## Requirements

- Rust **1.36+**

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

[crate-image]: https://img.shields.io/crates/v/signature.svg
[crate-link]: https://crates.io/crates/signature
[docs-image]: https://docs.rs/signature/badge.svg
[docs-link]: https://docs.rs/signature/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.36+-blue.svg
[build-image]: https://travis-ci.org/RustCrypto/signatures.svg?branch=master
[build-link]: https://travis-ci.org/RustCrypto/signatures

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Digital_signature
[2]: https://github.com/RustCrypto/signatures/tree/master/ed25519
[3]: https://github.com/RustCrypto/signatures/tree/master/ecdsa
[4]: https://github.com/RustCrypto/RSA
