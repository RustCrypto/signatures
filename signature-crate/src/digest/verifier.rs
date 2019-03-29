//! Support for verifying messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use crate::{digest::Digest, error::Error, Signature};

/// Verify the provided signature for the given prehashed message `Digest`
/// is authentic.
pub trait Verifier<D, S>
where
    D: Digest,
    S: Signature,
{
    /// Verify the signature against the given `Digest`
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Error>;
}

impl<S, T> crate::Verifier<S> for T
where
    S: crate::digest::Signature,
    T: Verifier<S::Digest, S>,
{
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        self.verify_digest(S::Digest::new().chain(msg), signature)
    }
}
