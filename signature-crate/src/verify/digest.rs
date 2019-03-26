//! Support for verifying messages which have been prehashed messages using
//! the `Digest` trait.
//!
//! For use signature algorithms that support an Initialize-Update-Finalize
//! (IUF) API, such as ECDSA or Ed25519ph.

use super::Verify;
use crate::{
    error::Error,
    signature::{RawDigestSignature, Signature},
};
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

/// Verify the given message using a "raw digest" signature algorithm, i.e.
/// any algorithm where signatures are always computed as `S(H(m)))` where:
///
/// - `S`: signature algorithm
/// - `H`: hash (a.k.a. digest) function
/// - `m`: message
///
/// This is the preferred trait to be `impl`'d for such algorithms, and when
/// used will take advantage of a blanket `impl` of `Sign` which will hash
/// the original message in advance using the relevant `Digest` algorithm
pub trait VerifyRawDigest<S>: Send + Sync
where
    S: Signature + RawDigestSignature,
{
    /// Digest algorithm to hash the input message with
    type Digest: Digest;

    /// Verify the signature against given prehashed message `Digest`
    fn verify_raw_digest(&self, digest: Self::Digest, signature: &S) -> Result<(), Error>;
}

impl<D, S, T> VerifyDigest<D, S> for T
where
    D: Digest,
    S: Signature + RawDigestSignature,
    T: VerifyRawDigest<S, Digest = D>,
{
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Error> {
        self.verify_raw_digest(digest, signature)
    }
}

impl<S, T> Verify<S> for T
where
    S: Signature + RawDigestSignature,
    T: VerifyRawDigest<S>,
{
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        self.verify_raw_digest(
            <T as VerifyRawDigest<S>>::Digest::new().chain(msg),
            signature,
        )
    }
}
