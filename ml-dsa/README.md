# [RustCrypto]: ML-DSA

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the Module-Lattice-Based Digital Signature Standard
(ML-DSA) as described in the [FIPS 204] (final).

## About

ML-DSA was formerly known as [CRYSTALS-Dilithium].

With the `alloc` feature, expanded matrix rows and cached key components are stored on the heap to
reduce construction and cloning stack usage. The opt-in `low-memory` feature regenerates public
matrix entries and secret NTTs instead of retaining them, and provides a reusable `SigningWorkspace`.
With `default-features = false`, this path needs no allocator. Enable `zeroize` to erase scratch after
signing. This trades additional SHAKE and NTT work for lower RAM usage. A caller-owned workspace can
reside in a static SRAM cell; existing signing methods construct it locally. See the
[Cortex-M33 stack probe](tools/cortex-m-stack) for reproduction instructions.

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## License

All crates licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[crate-image]: https://img.shields.io/crates/v/ml-dsa?logo=rust
[crate-link]: https://crates.io/crates/ml-dsa
[docs-image]: https://docs.rs/ml-dsa/badge.svg
[docs-link]: https://docs.rs/ml-dsa/
[build-image]: https://github.com/RustCrypto/signatures/actions/workflows/ml-dsa.yml/badge.svg
[build-link]: https://github.com/RustCrypto/signatures/actions/workflows/ml-dsa.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final
[CRYSTALS-Dilithium]: https://pq-crystals.org/dilithium/
