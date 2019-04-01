//! Traits for generating digital signatures

#[cfg(feature = "digest")]
use crate::{
    digest::{generic_array::GenericArray, Digest},
    signature::DigestSignature,
};
use crate::{error::Error, Signature};

/// Sign the provided message bytestring using `Self` (e.g. a cryptographic key
/// or connection to an HSM), returning a digital signature.
pub trait Signer<S: Signature> {
    /// Sign the given message and return a digital signature
    fn sign(&self, msg: &[u8]) -> Result<S, Error>;
}

/// Sign the given prehashed message `Digest` using `Self`.
#[cfg(feature = "digest")]
pub trait DigestSigner<D, S>
where
    D: Digest,
    S: Signature,
{
    /// Sign the given prehashed message `Digest`, returning a signature.
    fn sign_digest(&self, digest: GenericArray<u8, D::OutputSize>) -> Result<S, Error>;
}

#[cfg(feature = "digest")]
impl<S, T> Signer<S> for T
where
    S: DigestSignature,
    T: DigestSigner<S::Digest, S>,
{
    fn sign(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign_digest(S::Digest::digest(msg))
    }
}
