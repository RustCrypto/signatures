//! Support for using hash functions that impl the `Digest` trait in order
//! to hash the input message in order to compute a signature.

mod digestable;
mod signer;
mod verifier;

/// Re-export the `Digest` trait from the `digest` crate, as it's the main
/// trait this module depends on.
pub use ::digest::Digest;

pub use self::{digestable::Digestable, signer::Signer, verifier::Verifier};
