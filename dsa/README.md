# [RustCrypto]: DSA

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]
[![Project Chat][chat-image]][chat-link]

[Digital Signature Algorithm (DSA)][1] as specified in
[FIPS 186-4][2] (Digital Signature Standard).

[Documentation][docs-link]

## About

This crate provides an implementation of DSA in pure Rust.

It utilises the [`signature`] crate to provide an interface for creating and verifying signatures.  

## ⚠️ Security Warning

The DSA implementation contained in this crate has never been
independently audited for security.

It may contain timing variabilities or other sidechannels which could
potentially disclose secret information, including secret keys.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

This crate requires **Rust 1.65** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

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

[crate-image]: https://buildstats.info/crate/dsa
[crate-link]: https://crates.io/crates/dsa
[docs-image]: https://docs.rs/dsa/badge.svg
[docs-link]: https://docs.rs/dsa/
[build-image]: https://github.com/RustCrypto/signatures/actions/workflows/dsa.yml/badge.svg
[build-link]: https://github.com/RustCrypto/signatures/actions/workflows/dsa.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
[2]: https://csrc.nist.gov/publications/detail/fips/186/4/final

[//]: # (docs.rs definitions)

[`signature`]: https://docs.rs/signature
[`signature::Signer`]: https://docs.rs/signature/latest/signature/trait.Signer.html
[`signature::Verifier`]: https://docs.rs/signature/latest/signature/trait.Verifier.html
