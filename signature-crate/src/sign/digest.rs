//! Support for signing messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use crate::{error::Error, Signature};
use digest::Digest;

/// Sign the given prehashed message `Digest` using `Self`.
pub trait SignDigest<D, S>: Send + Sync
where
    D: Digest,
    S: Signature,
{
    /// Sign the given prehashed message `Digest`, returning a signature.
    fn sign(&self, digest: D) -> Result<S, Error>;
}
