use crate::{
    digest::{self, Digest},
    error::Error,
    signature::Signature,
    signer::Signer,
    verifier::Verifier,
};

/// Marker trait for `Signature` types computable as `S(H(m))` where:
///
/// - `S`: signature algorithm
/// - `H`: hash (a.k.a. digest) function
/// - `m`: message
///
/// For signature types that implement this trait, a blanket impl of
/// `Signer` will be provided for all types that `impl digest::Signer`.
pub trait Digestable: Signature {
    /// Preferred `Digest` algorithm to use when computing this signature type.
    type Digest: Digest;
}

impl<S, T> Signer<S> for T
where
    S: Digestable + Signature,
    T: digest::Signer<S::Digest, S>,
{
    fn sign(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign_digest(S::Digest::digest(msg))
    }
}

impl<S, T> Verifier<S> for T
where
    S: Digestable + Signature,
    T: digest::Verifier<S::Digest, S>,
{
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        self.verify_digest(S::Digest::digest(msg), signature)
    }
}
