//! Support for verifying messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use super::Verify;
use crate::{Error, Signature};
use digest::Digest;

/// Verify the provided signature for the given prehashed message `Digest`
/// is authentic.
pub trait VerifyDigest<D, S>: Send + Sync
where
    D: Digest,
    S: Signature,
{
    /// Verify the signature against the given `Digest`
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Error>;
}

/// Marker trait for digest verifiers who wish to use a blanket impl of the
/// `Verify` trait which works with any type that implements `VerifyDigest`
pub trait UseDigestToVerify {
    /// Digest type to use when verifying a signature
    type Digest: Digest;
}

impl<S, T> Verify<S> for T
where
    S: Signature,
    T: UseDigestToVerify + VerifyDigest<<T as UseDigestToVerify>::Digest, S>,
{
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        self.verify_digest(
            <T as UseDigestToVerify>::Digest::new().chain(msg),
            signature,
        )
    }
}
