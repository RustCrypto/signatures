# [RustCrypto]: Ed448

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

[Edwards Digital Signature Algorithm (EdDSA)][1] over Curve448 as specified
in [RFC 7748][2].

[Documentation][docs-link]

## About

This crate doesn't contain an implementation of Ed448, but instead
contains an [`ed448::Signature`][3] type which other crates can use in
conjunction with the [`signature::Signer`][4] and [`signature::Verifier`][5]
traits.

These traits allow crates which produce and consume Ed448 signatures
to be written abstractly in such a way that different signer/verifier
providers can be plugged in, enabling support for using different
Ed448 implementations, including HSMs or Cloud KMS services.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above
- The `pkcs8` module is exempted as it uses a pre-1.0 dependency, however,
  breaking changes to this module will be accompanied by a minor version bump.

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

[crate-image]: https://img.shields.io/crates/v/ed448?logo=rust
[crate-link]: https://crates.io/crates/ed448
[docs-image]: https://docs.rs/ed448/badge.svg
[docs-link]: https://docs.rs/ed448/
[build-image]: https://github.com/RustCrypto/signatures/actions/workflows/ed448.yml/badge.svg
[build-link]: https://github.com/RustCrypto/signatures/actions/workflows/ed448.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/EdDSA#Ed448
[2]: https://tools.ietf.org/html/rfc7748
[3]: https://docs.rs/ed448/latest/ed448/struct.Signature.html
[4]: https://docs.rs/signature/latest/signature/trait.Signer.html
[5]: https://docs.rs/signature/latest/signature/trait.Verifier.html
