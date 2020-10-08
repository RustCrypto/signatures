//! ECDSA signing key. Generic over elliptic curves.
//!
//! Requires an [`elliptic_curve::ProjectiveArithmetic`] impl on the curve, and a
//! [`SignPrimitive`] impl on its associated `Scalar` type.

// TODO(tarcieri): support for hardware crypto accelerators

use crate::{
    hazmat::{DigestPrimitive, SignPrimitive},
    rfc6979, Error, Signature, SignatureSize,
};
use core::convert::TryInto;
use elliptic_curve::{
    ff::PrimeField,
    generic_array::ArrayLength,
    ops::Invert,
    scalar::{NonZeroScalar, Scalar},
    subtle::ConstantTimeEq,
    weierstrass::Curve,
    zeroize::Zeroize,
    FieldBytes, FromDigest, ProjectiveArithmetic, SecretKey,
};
use signature::{
    digest::{BlockInput, Digest, FixedOutput, Reset, Update},
    rand_core::{CryptoRng, RngCore},
    DigestSigner, RandomizedDigestSigner, RandomizedSigner,
};

#[cfg(feature = "verify")]
use {
    crate::verify::VerifyKey,
    core::fmt::Debug,
    elliptic_curve::{
        group::{Curve as _, Group},
        AffinePoint,
    },
};

/// ECDSA signing key
pub struct SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    secret_scalar: NonZeroScalar<C>,
}

impl<C> SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Generate a cryptographically random [`SigningKey`].
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            secret_scalar: NonZeroScalar::random(rng),
        }
    }

    /// Initialize signing key from a raw scalar serialized as a byte slice.
    // TODO(tarcieri): PKCS#8 support
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .ok()
            .map(|secret_scalar| Self { secret_scalar })
            .ok_or_else(Error::new)
    }

    /// Get the [`VerifyKey`] which corresponds to this [`SigningKey`]
    #[cfg(feature = "verify")]
    #[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
    pub fn verify_key(&self) -> VerifyKey<C>
    where
        AffinePoint<C>: Clone + Debug,
    {
        #[allow(clippy::op_ref)]
        let public_key = (C::ProjectivePoint::generator() * &*self.secret_scalar).to_affine();
        VerifyKey { public_key }
    }

    /// Serialize this [`SigningKey`] as bytes
    pub fn to_bytes(&self) -> FieldBytes<C> {
        self.secret_scalar.to_repr()
    }
}

impl<C> From<&SecretKey<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + ConstantTimeEq
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_key: &SecretKey<C>) -> Self {
        // TODO(tarcieri): better conversion
        Self::new(&secret_key.secret_scalar().to_repr()).expect("invalid secret scalar")
    }
}

impl<C, D> DigestSigner<D, Signature<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    D: FixedOutput<OutputSize = C::FieldSize> + BlockInput + Clone + Default + Reset + Update,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Sign message prehash using a deterministic ephemeral scalar (`k`)
    /// computed using the algorithm described in RFC 6979 (Section 3.2):
    /// <https://tools.ietf.org/html/rfc6979#section-3>
    fn try_sign_digest(&self, digest: D) -> Result<Signature<C>, Error> {
        let ephemeral_scalar = rfc6979::generate_k(&self.secret_scalar, digest.clone(), &[]);
        let msg_scalar = Scalar::<C>::from_digest(digest);

        self.secret_scalar
            .try_sign_prehashed(ephemeral_scalar.as_ref(), &msg_scalar)
    }
}

impl<C> signature::Signer<Signature<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic + DigestPrimitive,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
    Self: DigestSigner<C::Digest, Signature<C>>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, signature::Error> {
        self.try_sign_digest(C::Digest::new().chain(msg))
    }
}

impl<C, D> RandomizedDigestSigner<D, Signature<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    D: FixedOutput<OutputSize = C::FieldSize> + BlockInput + Clone + Default + Reset + Update,
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
        let mut added_entropy = FieldBytes::<C>::default();
        rng.fill_bytes(&mut added_entropy);

        let ephemeral_scalar =
            rfc6979::generate_k(&self.secret_scalar, digest.clone(), &added_entropy);

        let msg_scalar = Scalar::<C>::from_digest(digest);

        self.secret_scalar
            .try_sign_prehashed(ephemeral_scalar.as_ref(), &msg_scalar)
    }
}

impl<C> RandomizedSigner<Signature<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic + DigestPrimitive,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
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

impl<C> From<NonZeroScalar<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_scalar: NonZeroScalar<C>) -> Self {
        Self { secret_scalar }
    }
}

impl<C> Zeroize for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.secret_scalar.zeroize();
    }
}

impl<C> Drop for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "verify")]
impl<C> From<&SigningKey<C>> for VerifyKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>
        + FromDigest<C>
        + Invert<Output = Scalar<C>>
        + SignPrimitive<C>
        + Zeroize,
    AffinePoint<C>: Clone + Debug,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(signing_key: &SigningKey<C>) -> VerifyKey<C> {
        signing_key.verify_key()
    }
}
