//! Trait for verifying digital signatures

#[cfg(feature = "digest")]
use crate::digest::{generic_array::GenericArray, Digest};
use crate::{error::Error, Signature};

/// Verify the provided message bytestring using `Self` (e.g. a public key)
pub trait Verifier<S: Signature> {
    /// Use `Self` to verify that the provided signature for a given message
    /// bytestring is authentic.
    ///
    /// Returns `Error` if it is inauthentic, or otherwise returns `()`.
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error>;
}

/// Verify the provided signature for the given prehashed message `Digest`
/// is authentic.
#[cfg(feature = "digest")]
pub trait DigestVerifier<D, S>
where
    D: Digest,
    S: Signature,
{
    /// Verify the signature against the computed `Digest` output.
    fn verify_msg_digest(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        self.verify_digest(D::digest(msg), signature)
    }

    /// Verify the signature against the given `Digest` output.
    fn verify_digest(
        &self,
        digest: GenericArray<u8, D::OutputSize>,
        signature: &S,
    ) -> Result<(), Error>;
}
