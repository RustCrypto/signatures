//! Support for signing messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use super::Digest;
use crate::{error::Error, signature::Signature};
use digest::generic_array::GenericArray;

/// Sign the given prehashed message `Digest` using `Self`.
pub trait Signer<D, S>
where
    D: Digest,
    S: Signature,
{
    /// Sign the given prehashed message `Digest`, returning a signature.
    fn sign_digest(&self, digest: GenericArray<u8, D::OutputSize>) -> Result<S, Error>;
}
