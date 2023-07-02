# [RustCrypto]: Ed448

[Edwards Digital Signature Algorithm (EdDSA)][1] over Curve448 as specified
in [RFC 7748][2].

## About

This crate doesn't contain an implementation of Ed448.

These traits allow crates which produce and consume Ed448 signatures
to be written abstractly in such a way that different signer/verifier
providers can be plugged in, enabling support for using different
Ed448 implementations, including HSMs or Cloud KMS services.

## Minimum Supported Rust Version

This crate requires **Rust 1.60** at a minimum.

Our policy is to allow MSRV to be raised in future released without that
qualifing as a SemVer-breaking change, but it will be accompanied by a minor
version bump, ensuring if you lock to a minor version MSRV will be preserved
for the default feature set.

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

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/EdDSA#Ed448
[2]: https://tools.ietf.org/html/rfc7748
