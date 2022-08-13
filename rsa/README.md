# [RustCrypto]: RSA

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]
[![Project Chat][chat-image]][chat-link]

[Rivest-Shamir-Adleman cryptosystem (RSA)][1] as specified in
[RFC 8017][2] (PKCS #1: RSA Cryptography Specifications Version 2.2).

## About

This crate provides generic RSA support which can be used in the following
ways:

- Generic implementation of ECDSA usable with the following crates:
  - [`rsa`] (rsa)
- Other crates which provide their own complete implementations of RSA can
  also leverage the types from this crate to export RSA functionality in a
  generic, interoperable way by leveraging [`rsa-signature::Signature`] with the
  [`signature::Signer`] and [`signature::Verifier`] traits.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/rsa-signature
[crate-link]: https://crates.io/crates/rsa-signature
[docs-image]: https://docs.rs/rsa-signature/badge.svg
[docs-link]: https://docs.rs/rsa-signature/
[build-image]: https://github.com/RustCrypto/signatures/actions/workflows/rsa-signature.yml/badge.svg
[build-link]: https://github.com/RustCrypto/signatures/actions/workflows/rsa-signature.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.57+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
[2]: https://www.rfc-editor.org/rfc/rfc8017

[//]: # (docs.rs definitions)

[`rsa`]: https://doc.rs/rsa
[`rsa-signature::Signature`]: https://docs.rs/rsa-signature/latest/rsa-signature/struct.Signature.html
[`signature::Signer`]: https://docs.rs/signature/latest/signature/trait.Signer.html
[`signature::Verifier`]: https://docs.rs/signature/latest/signature/trait.Verifier.html
