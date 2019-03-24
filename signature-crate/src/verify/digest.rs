//! Support for verifying messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use crate::{error::Error, Signature};
use digest::Digest;

/// Verify the provided signature for the given prehashed message `Digest`
/// is authentic.
pub trait VerifyDigest<D, S>: Send + Sync
where
    D: Digest,
    S: Signature,
{
    /// Verify the signature against the given `Digest`
    fn verify(&self, digest: D, signature: &S) -> Result<(), Error>;
}
