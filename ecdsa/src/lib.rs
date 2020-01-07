//! Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
//! [FIPS 186-4][1] (Digital Signature Standard)
//!
//! This crate doesn't contain an implementation of ECDSA itself, but instead
//! contains [`Asn1Signature`] and [`FixedSignature`] types which are generic
//! over elliptic [`Curve`] types (e.g. `NistP256`, `NistP384`, `Secp256k1`)
//! which can be used in conjunction with the [`signature::Signer`] and
//! [`signature::Verifier`] traits to provide signature types which are
//! reusable across multiple signing and verification provider crates.
//!
//! Transcoding between [`Asn1Signature`] and [`FixedSignature`] of the same
//! [`Curve`] type is supported in the form of simple `From` impls.
//!
//! Additionally, the [`PublicKey`] and [`SecretKey`] types, also generic
//! over elliptic curve types, provide reusable key types, sourced from the
//! [`elliptic-curve`][2] crate. The [`PublicKey`] type supports both
//! compressed and uncompressed points, and for the P-256 curve in particular
//! supports converting between the compressed and uncompressed forms.
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
//! [2]: http://docs.rs/elliptic-curve

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, intra_doc_link_resolution_failure)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png",
    html_root_url = "https://docs.rs/ecdsa/0.4.0"
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

pub use self::{asn1_signature::Asn1Signature, fixed_signature::FixedSignature};
pub use elliptic_curve::{
    weierstrass::{Curve, PublicKey},
    SecretKey,
};
