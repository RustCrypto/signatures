# RustCrypto: signatures
[![Build Status](https://travis-ci.org/RustCrypto/signatures.svg?branch=master)](https://travis-ci.org/RustCrypto/signatures)

Traits which provide generic, object-safe APIs for generating and verifying
[digital signatures][1].

All algorithms reside in the separate crates and implemented using traits from
the [`signature`](https://docs.rs/signature/) crate. Additionally all crates do
not require the standard library (i.e. `no_std` capable) and can be easily used
for bare-metal or WebAssembly programming.

## Supported algorithms

- [ECDSA][2]
- [Ed25519][3]

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[1]: https://en.wikipedia.org/wiki/Digital_signature
[2]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[3]: https://en.wikipedia.org/wiki/EdDSA
