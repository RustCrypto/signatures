//! Support for signing messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use super::Sign;
use crate::{Error, Signature};
use digest::Digest;

/// Sign the given prehashed message `Digest` using `Self`.
pub trait SignDigest<S>: Send + Sync
where
    S: Signature,
{
    /// Digest type to use when computing a signature
    type Digest: Digest;

    /// Sign the given prehashed message `Digest`, returning a signature.
    fn sign_digest(&self, digest: Self::Digest) -> Result<S, Error>;
}

/// Marker trait for digest verifiers who wish to use a blanket impl of the
/// `Sign` trait which works with any type that implements `SignDigest`
pub trait UseDigestToSign {}

impl<S, T> Sign<S> for T
where
    S: Signature,
    T: SignDigest<S> + UseDigestToSign,
{
    fn sign(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign_digest(<Self as SignDigest<S>>::Digest::new().chain(msg))
    }
}
