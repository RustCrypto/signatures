//! ECDSA signer. Generic over elliptic curves.
//!
//! Requires an [`elliptic_curve::Arithmetic`] impl on the curve, and a
//! [`SignPrimitive`] impl on its associated `Scalar` type.

// TODO(tarcieri): support for hardware crypto accelerators

pub mod rfc6979;

use crate::{
    hazmat::{DigestPrimitive, SignPrimitive},
    Error, Signature, SignatureSize,
};
use core::convert::TryInto;
use elliptic_curve::{
    generic_array::ArrayLength, ops::Invert, scalar::NonZeroScalar, weierstrass::Curve,
    zeroize::Zeroize, Arithmetic, FromBytes, FromDigest, SecretKey,
};
use signature::{
    digest::{BlockInput, Digest, FixedOutput, Reset, Update},
    DigestSigner,
};

#[cfg(feature = "rand")]
use {
    elliptic_curve::ElementBytes,
    signature::{
        rand_core::{CryptoRng, RngCore},
        RandomizedDigestSigner, RandomizedSigner,
    },
};

/// ECDSA signer
pub struct Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    secret_scalar: NonZeroScalar<C>,
}

impl<C> Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Initialize signer from a raw scalar serialized as a byte slice
    // TODO(tarcieri): PKCS#8 support
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let scalar = bytes
            .try_into()
            .map(NonZeroScalar::from_bytes)
            .map_err(|_| Error::new())?;

        // TODO(tarcieri): replace with into conversion when available (see subtle#73)
        if scalar.is_some().into() {
            Ok(Self::from(scalar.unwrap()))
        } else {
            Err(Error::new())
        }
    }

    /// Create a new signer
    // TODO(tarcieri): infallible conversion from a secret key
    pub fn new(secret_key: &SecretKey<C>) -> Result<Self, Error> {
        Self::from_bytes(secret_key.as_bytes())
    }
}

impl<C, D> DigestSigner<D, Signature<C>> for Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    D: FixedOutput<OutputSize = C::ElementSize> + BlockInput + Clone + Default + Reset + Update,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Sign message prehash using a deterministic ephemeral scalar (`k`)
    /// computed using the algorithm described in RFC 6979 (Section 3.2):
    /// <https://tools.ietf.org/html/rfc6979#section-3>
    fn try_sign_digest(&self, digest: D) -> Result<Signature<C>, Error> {
        let ephemeral_scalar = rfc6979::generate_k(&self.secret_scalar, digest.clone(), &[]);
        let msg_scalar = C::Scalar::from_digest(digest);

        self.secret_scalar
            .try_sign_prehashed(ephemeral_scalar.as_ref(), &msg_scalar)
    }
}

impl<C> signature::Signer<Signature<C>> for Signer<C>
where
    C: Curve + Arithmetic + DigestPrimitive,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
    Self: DigestSigner<C::Digest, Signature<C>>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, signature::Error> {
        self.try_sign_digest(C::Digest::new().chain(msg))
    }
}

#[cfg(feature = "rand")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
impl<C, D> RandomizedDigestSigner<D, Signature<C>> for Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    D: FixedOutput<OutputSize = C::ElementSize> + BlockInput + Clone + Default + Reset + Update,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Sign message prehash using an ephemeral scalar (`k`) derived according
    /// to a variant of RFC 6979 (Section 3.6) which supplies additional
    /// entropy from an RNG.
    fn try_sign_digest_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> Result<Signature<C>, Error> {
        let mut added_entropy = ElementBytes::<C>::default();
        rng.fill_bytes(&mut added_entropy);

        let ephemeral_scalar =
            rfc6979::generate_k(&self.secret_scalar, digest.clone(), &added_entropy);

        let msg_scalar = C::Scalar::from_digest(digest);

        self.secret_scalar
            .try_sign_prehashed(ephemeral_scalar.as_ref(), &msg_scalar)
    }
}

#[cfg(feature = "rand")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
impl<C> RandomizedSigner<Signature<C>> for Signer<C>
where
    C: Curve + Arithmetic + DigestPrimitive,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
    Self: RandomizedDigestSigner<C::Digest, Signature<C>>,
{
    fn try_sign_with_rng(
        &self,
        rng: impl CryptoRng + RngCore,
        msg: &[u8],
    ) -> Result<Signature<C>, Error> {
        self.try_sign_digest_with_rng(rng, C::Digest::new().chain(msg))
    }
}

impl<C> From<NonZeroScalar<C>> for Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_scalar: NonZeroScalar<C>) -> Self {
        Self { secret_scalar }
    }
}

impl<C> Zeroize for Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.secret_scalar.zeroize();
    }
}

impl<C> Drop for Signer<C>
where
    C: Curve + Arithmetic,
    C::Scalar: FromDigest<C> + Invert<Output = C::Scalar> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}
