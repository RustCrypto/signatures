//! Support for verifying messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use super::Digest;
use crate::{error::Error, signature::Signature};

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
