# [RustCrypto]: XMSS

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the XMSS (eXtended Merkle Signature Scheme)
and XMSS^MT (Multi-Tree) signature schemes as described in [RFC 8391] and
[NIST SP 800-208].

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## About

XMSS is a stateful hash-based digital signature scheme that is believed to be
resistant to attacks by quantum computers. It is standardized in [RFC 8391] and
approved by NIST in [SP 800-208].

This crate provides:

- XMSS (single-tree) and XMSS^MT (multi-tree) signature schemes
- SHA-256, SHA-512, SHAKE128, and SHAKE256 hash function support
- 93 parameter sets covering tree heights of 10, 16, 20, 40, and 60
- Hash output sizes of 192, 256, and 512 bits
- Optional `serde` support for serialization/deserialization
- Optional `pkcs8` support for PKCS#8/SPKI key encoding
- `no_unsafe` code — zero `unsafe` blocks
- Constant-time operations for signature verification
- Automatic zeroization of secret key material on drop

## Usage

```rust
use xmss_signatures::{KeyPair, XmssSha2_10_256};

// Generate a key pair
let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rand::rng()).unwrap();

// Sign a message
let message = b"test message";
let signature = kp.signing_key().sign(message).unwrap();

// Verify the signature and recover the message
let recovered = kp.verifying_key().verify(&signature).unwrap();
assert_eq!(recovered, message);

// Detached signatures are also supported
let signature = kp.signing_key().sign_detached(message).unwrap();
kp.verifying_key().verify_detached(&signature, message).unwrap();
```

## Supported Parameter Sets

### XMSS (Single-Tree)

| Parameter Set | Hash | n (bytes) | Tree Height | Max Signatures |
|---|---|---|---|---|
| `XmssSha2_10_256` | SHA-256 | 32 | 10 | 1,024 |
| `XmssSha2_16_256` | SHA-256 | 32 | 16 | 65,536 |
| `XmssSha2_20_256` | SHA-256 | 32 | 20 | 1,048,576 |
| `XmssSha2_10_512` | SHA-512 | 64 | 10 | 1,024 |
| `XmssSha2_16_512` | SHA-512 | 64 | 16 | 65,536 |
| `XmssSha2_20_512` | SHA-512 | 64 | 20 | 1,048,576 |
| `XmssSha2_10_192` | SHA-256 | 24 | 10 | 1,024 |
| `XmssSha2_16_192` | SHA-256 | 24 | 16 | 65,536 |
| `XmssSha2_20_192` | SHA-256 | 24 | 20 | 1,048,576 |
| `XmssShake_10_256` | SHAKE128 | 32 | 10 | 1,024 |
| `XmssShake_16_256` | SHAKE128 | 32 | 16 | 65,536 |
| `XmssShake_20_256` | SHAKE128 | 32 | 20 | 1,048,576 |
| `XmssShake_10_512` | SHAKE128 | 64 | 10 | 1,024 |
| `XmssShake_16_512` | SHAKE128 | 64 | 16 | 65,536 |
| `XmssShake_20_512` | SHAKE128 | 64 | 20 | 1,048,576 |
| `XmssShake256_10_256` | SHAKE256 | 32 | 10 | 1,024 |
| `XmssShake256_16_256` | SHAKE256 | 32 | 16 | 65,536 |
| `XmssShake256_20_256` | SHAKE256 | 32 | 20 | 1,048,576 |
| `XmssShake256_10_192` | SHAKE256 | 24 | 10 | 1,024 |
| `XmssShake256_16_192` | SHAKE256 | 24 | 16 | 65,536 |
| `XmssShake256_20_192` | SHAKE256 | 24 | 20 | 1,048,576 |

### XMSS^MT (Multi-Tree)

Multi-tree parameter sets follow the naming convention
`Xmssmt[Hash]_[TotalHeight]_[Depth]_[Bits]`, e.g. `XmssmtSha2_20_2_256`.

Total tree heights of 20, 40, and 60 are supported with depths of 2, 4, 8, 3,
6, and 12 (where applicable), across SHA-256, SHA-512, SHAKE128, and SHAKE256
hash functions.

See the [API documentation][docs-link] for a complete list of all 72 XMSS^MT
parameter sets.

## Features

| Feature | Description |
|---|---|
| `serde` | Enables `serde` serialization/deserialization via `serdect` |
| `pkcs8` | Enables PKCS#8 and SPKI key encoding/decoding |

## Minimum Supported Rust Version

This crate requires **Rust 2024 edition**.

## License

All crates licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/xmss-signatures?logo=rust
[crate-link]: https://crates.io/crates/xmss-signatures
[docs-image]: https://docs.rs/xmss-signatures/badge.svg
[docs-link]: https://docs.rs/xmss-signatures/
[build-image]: https://github.com/RustCrypto/signatures/actions/workflows/xmss.yml/badge.svg
[build-link]: https://github.com/RustCrypto/signatures/actions/workflows/xmss.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[RFC 8391]: https://www.rfc-editor.org/rfc/rfc8391
[NIST SP 800-208]: https://csrc.nist.gov/pubs/sp/800/208/final
