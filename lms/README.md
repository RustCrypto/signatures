# [RustCrypto]: Leighton-Micali Signatures

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]
[![Project Chat][chat-image]][chat-link]

This repository contains implementations of [Leighton-Micali Hash-Based
Signatures (RFC 8554)](https://datatracker.ietf.org/doc/html/rfc8554).

## Security Notice

LMS signatures are stateful: Users must take care to never sign more than one
message with the same internal LM-OTS private key. To avoid catastrophe, state
must be maintained across multiple invocations of the signing algorithm.

When using our LMS implementations, the internal counter (`q`) will be
incremented before each signature is returned.

If the LMS private key is persisted to storage, you **MUST** update the
persistent storage after each signature is generated and before it is released
to the rest of the application. Failure to adhere to this requirement is a
security vulnerability in your application.

For a stateless hash-based signature algorithm, see [SLH-DSA].

NOTE: this project has not been externally audited, but the entire codebase
was internally reviewed by cryptographers at Trail of Bits.

## Installation

```terminal
cargo install
```

## Usage

Our implementation uses strongly typed private and public key types.

```rust
let mut rng = thread_rng();
let mut seckey = lms::lms::PrivateKey::new::<LmsSha256M32H10<LmsOtsSha256N32W4> > ( & mut rng);
let pubkey = seckey.public();   // of type lms::lms::PublicKey<LmsSha256M32H10>
let sig    = seckey.try_sign_with_rng( & mut rng, "example".as_bytes()).unwrap();
let sig_valid = pubkey.verify("example".as_bytes(), & sig).is_ok();
```

We can generate LMOTS signatures in the same way using `lms::ots::PrivateKey`
instead.

### Key Management

We do not require much from the user in terms of key management. Any internal
state changing operation uses mutable reference to update the internal state.
When persisting private keys to long term storage, users must be very careful
that **the same private key is never read from disk twice**. This would create
two private keys in the same state and thus when they are both used to sign a
message, the LMOTS private keys will have been reused, which is considered **not
good**.

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/lms-signature
[crate-link]: https://crates.io/crates/lms-signature
[docs-image]: https://docs.rs/lms-signature/badge.svg
[docs-link]: https://docs.rs/lms-signature/
[build-image]: https://github.com/RustCrypto/signatures/actions/workflows/lms.yml/badge.svg
[build-link]: https://github.com/RustCrypto/signatures/actions/workflows/lms.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.73+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[SLH-DSA]: https://github.com/RustCrypto/signatures/tree/master/slh-dsa
