# RustCrypto: ECDSA

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]
[![Build Status][build-image]][build-link]

[Elliptic Curve Digital Signature Algorithm (ECDSA)][1] as specified in
[FIPS 186-4][2] (Digital Signature Standard).

This crate doesn't contain an implementation of ECDSA itself, but instead
contains [`ecdsa::Asn1Signature`][3] and [`ecdsa::FixedSignature`][4] types
generic over an [`ecdsa::Curve`][5] type which other crates can use in
conjunction with the [`signature::Signer`][6] and [`signature::Verifier`][7]
traits.

These traits allow crates which produce and consume ECDSA signatures
to be written abstractly in such a way that different signer/verifier
providers can be plugged in, enabling support for using different
ECDSA implementations, including HSMs or Cloud KMS services.

[Documentation][docs-link]

## Minimum Supported Rust Version

- Rust **1.41+**

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
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[build-image]: https://github.com/RustCrypto/signatures/workflows/ecdsa/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/signatures/actions?query=workflow%3Aecdsa

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[2]: https://csrc.nist.gov/publications/detail/fips/186/4/final
[3]: https://docs.rs/ecdsa/latest/ecdsa/asn1_signature/struct.Asn1Signature.html
[4]: https://docs.rs/ecdsa/latest/ecdsa/fixed_signature/struct.FixedSignature.html
[5]: https://docs.rs/ecdsa/latest/ecdsa/curve/trait.Curve.html
[6]: https://docs.rs/signature/latest/signature/trait.Signer.html
[7]: https://docs.rs/signature/latest/signature/trait.Verifier.html
