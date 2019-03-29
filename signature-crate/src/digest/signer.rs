//! Support for signing messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use crate::{digest::Digest, error::Error, Signature};

/// Sign the given prehashed message `Digest` using `Self`.
pub trait Signer<D, S>
where
    D: Digest,
    S: Signature,
{
    /// Sign the given prehashed message `Digest`, returning a signature.
    fn sign_digest(&self, digest: D) -> Result<S, Error>;
}

impl<S, T> crate::Signer<S> for T
where
    S: crate::digest::Signature,
    T: Signer<S::Digest, S>,
{
    fn sign(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign_digest(S::Digest::new().chain(msg))
    }
}
