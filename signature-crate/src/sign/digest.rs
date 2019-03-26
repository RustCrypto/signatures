//! Support for signing messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use super::Sign;
use crate::{
    error::Error,
    signature::{RawDigestSignature, Signature},
};
use digest::Digest;

/// Sign the given prehashed message `Digest` using `Self`.
pub trait SignDigest<D, S>: Send + Sync
where
    D: Digest,
    S: Signature,
{
    /// Sign the given prehashed message `Digest`, returning a signature.
    fn sign_digest(&self, digest: D) -> Result<S, Error>;
}

/// Sign the given message using a "raw digest" signature algorithm, i.e.
/// any algorithm where signatures are always computed as `S(H(m)))` where:
///
/// - `S`: signature algorithm
/// - `H`: hash (a.k.a. digest) function
/// - `m`: message
///
/// This is the preferred trait to be `impl`'d for such algorithms, and when
/// used will take advantage of a blanket `impl` of `Sign` which will hash
/// the original message in advance using the relevant `Digest` algorithm
pub trait SignRawDigest<S>: Send + Sync
where
    S: Signature + RawDigestSignature,
{
    /// Digest algorithm to hash the input message with
    type Digest: Digest;

    /// Sign the given prehashed message `Digest`, returning a signature.
    fn sign_raw_digest(&self, digest: Self::Digest) -> Result<S, Error>;
}

impl<D, S, T> SignDigest<D, S> for T
where
    D: Digest,
    S: Signature + RawDigestSignature,
    T: SignRawDigest<S, Digest = D>,
{
    fn sign_digest(&self, digest: D) -> Result<S, Error> {
        self.sign_raw_digest(digest)
    }
}

impl<S, T> Sign<S> for T
where
    S: Signature + RawDigestSignature,
    T: SignRawDigest<S>,
{
    fn sign(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign_digest(<T as SignRawDigest<S>>::Digest::new().chain(msg))
    }
}
