//! Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
//! [FIPS 186-4][1] (Digital Signature Standard)
//!
//! This crate doesn't contain an implementation of ECDSA itself, but instead
//! contains [`ecdsa::Asn1Signature`] and [`ecdsa::FixedSignature`] types
//! generic over an [`ecdsa::Curve`] type which other crates can use in
//! conjunction with the [`signature::Signer`] and [`signature::Verifier`]
//! traits.
//!
//! These traits allow crates which produce and consume ECDSA signatures
//! to be written abstractly in such a way that different signer/verifier
//! providers can be plugged in, enabling support for using different
//! ECDSA implementations, including HSMs or Cloud KMS services.
//!
//! ## TODO
//!
//! - NIST P-521
//! - Brainpool
//! - Const generics(!)
//!
//! [1]: https://csrc.nist.gov/publications/detail/fips/186/4/final

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, intra_doc_link_resolution_failure)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png",
    html_root_url = "https://docs.rs/ecdsa/0.2.0"
)]

// Re-export the `generic-array` crate
pub use generic_array;

// Re-export the `signature` crate
pub use signature;

pub mod asn1_signature;
mod convert;
pub mod curve;
pub mod fixed_signature;
#[cfg(feature = "test-vectors")]
pub mod test_vectors;

pub use self::{asn1_signature::Asn1Signature, curve::Curve, fixed_signature::FixedSignature};
