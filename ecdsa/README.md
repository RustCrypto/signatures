# `ecdsa` crate

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]
[![Build Status][build-image]][build-link]

Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
[FIPS 186-4][1] (Digital Signature Standard).

This crate doesn't contain an implementation of ECDSA itself, but instead
contains [`ecdsa::Asn1Signature`][2] and [`ecdsa::FixedSignature`][3] types
generic over an [`ecdsa::Curve`][4] type which other crates can use in
conjunction with the [`signature::Signer`][5] and [`signature::Verifier`][6]
traits.

These traits allow crates which produce and consume ECDSA signatures
to be written abstractly in such a way that different signer/verifier
providers can be plugged in, enabling support for using different
ECDSA implementations, including HSMs or Cloud KMS services.

[Documentation][docs-link]

## Requirements

- Rust **1.37+**

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

[crate-image]: https://img.shields.io/crates/v/ecdsa.svg
[crate-link]: https://crates.io/crates/ecdsa
[docs-image]: https://docs.rs/ecdsa/badge.svg
[docs-link]: https://docs.rs/ecdsa/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.37+-blue.svg
[build-image]: https://travis-ci.org/RustCrypto/signatures.svg?branch=master
[build-link]: https://travis-ci.org/RustCrypto/signatures

[//]: # (general links)

[1]: https://csrc.nist.gov/publications/detail/fips/186/4/final
[2]: https://docs.rs/ecdsa/latest/ecdsa/asn1_signature/struct.Asn1Signature.html
[3]: https://docs.rs/ecdsa/latest/ecdsa/fixed_signature/struct.FixedSignature.html
[4]: https://docs.rs/ecdsa/latest/ecdsa/curve/trait.Curve.html
[5]: https://docs.rs/signature/latest/signature/trait.Signer.html
[6]: https://docs.rs/signature/latest/signature/trait.Verifier.html
