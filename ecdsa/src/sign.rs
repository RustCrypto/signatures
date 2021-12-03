//! ECDSA signing key.

// TODO(tarcieri): support for hardware crypto accelerators

use crate::{
    hazmat::{rfc6979_generate_k, DigestPrimitive, SignPrimitive},
    Error, Result, Signature, SignatureSize,
};
use core::fmt::{self, Debug};
use elliptic_curve::{
    generic_array::ArrayLength,
    group::ff::PrimeField,
    ops::{Invert, Reduce},
    subtle::{Choice, ConstantTimeEq},
    zeroize::Zeroize,
    FieldBytes, FieldSize, NonZeroScalar, PrimeCurve, ProjectiveArithmetic, Scalar, SecretKey,
};
use signature::{
    digest::{BlockInput, Digest, FixedOutput, Reset, Update},
    rand_core::{CryptoRng, RngCore},
    DigestSigner, RandomizedDigestSigner, RandomizedSigner, Signer,
};

#[cfg(feature = "verify")]
use {crate::verify::VerifyingKey, elliptic_curve::PublicKey};

#[cfg(feature = "pkcs8")]
use crate::elliptic_curve::{
    pkcs8::{self, DecodePrivateKey},
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    AffinePoint, AlgorithmParameters,
};

#[cfg(feature = "pem")]
use core::str::FromStr;

/// ECDSA signing key. Generic over elliptic curves.
///
/// Requires an [`elliptic_curve::ProjectiveArithmetic`] impl on the curve, and a
/// [`SignPrimitive`] impl on its associated `Scalar` type.
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub struct SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    inner: NonZeroScalar<C>,
}

impl<C> SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Generate a cryptographically random [`SigningKey`].
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            inner: NonZeroScalar::random(rng),
        }
    }

    /// Initialize signing key from a raw scalar serialized as a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = SecretKey::from_be_bytes(bytes)
            .map(|sk| sk.to_nonzero_scalar())
            .map_err(|_| Error::new())?;

        Ok(Self { inner })
    }

    /// Get the [`VerifyingKey`] which corresponds to this [`SigningKey`]
    #[cfg(feature = "verify")]
    #[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
    pub fn verifying_key(&self) -> VerifyingKey<C> {
        VerifyingKey {
            inner: PublicKey::from_secret_scalar(&self.inner),
        }
    }

    /// Serialize this [`SigningKey`] as bytes
    pub fn to_bytes(&self) -> FieldBytes<C> {
        self.inner.to_repr()
    }
}

impl<C> ConstantTimeEq for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl<C> Debug for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO(tarcieri): use `finish_non_exhaustive` when stable
        f.debug_tuple("SigningKey").field(&"...").finish()
    }
}

impl<C> Drop for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Constant-time comparison
impl<C> Eq for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
}

/// Constant-time comparison
impl<C> PartialEq for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn eq(&self, other: &SigningKey<C>) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C> From<SecretKey<C>> for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_key: SecretKey<C>) -> Self {
        Self::from(&secret_key)
    }
}

impl<C> From<&SecretKey<C>> for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_key: &SecretKey<C>) -> Self {
        Self {
            inner: secret_key.to_nonzero_scalar(),
        }
    }
}

impl<C, D> DigestSigner<D, Signature<C>> for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    D: FixedOutput<OutputSize = FieldSize<C>> + BlockInput + Clone + Default + Reset + Update,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Sign message prehash using a deterministic ephemeral scalar (`k`)
    /// computed using the algorithm described in RFC 6979 (Section 3.2):
    /// <https://tools.ietf.org/html/rfc6979#section-3>
    fn try_sign_digest(&self, msg_digest: D) -> Result<Signature<C>> {
        let msg_scalar = Scalar::<C>::from_be_bytes_reduced(msg_digest.finalize_fixed());
        let k = rfc6979_generate_k::<C, D>(&self.inner, &msg_scalar, &[]);
        Ok(self.inner.try_sign_prehashed(**k, msg_scalar)?.0)
    }
}

impl<C> Signer<Signature<C>> for SigningKey<C>
where
    Self: DigestSigner<C::Digest, Signature<C>>,
    C: PrimeCurve + ProjectiveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>> {
        self.try_sign_digest(C::Digest::new().chain(msg))
    }
}

impl<C, D> RandomizedDigestSigner<D, Signature<C>> for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    D: FixedOutput<OutputSize = FieldSize<C>> + BlockInput + Clone + Default + Reset + Update,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Sign message prehash using an ephemeral scalar (`k`) derived according
    /// to a variant of RFC 6979 (Section 3.6) which supplies additional
    /// entropy from an RNG.
    fn try_sign_digest_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        msg_digest: D,
    ) -> Result<Signature<C>> {
        let mut entropy = FieldBytes::<C>::default();
        rng.fill_bytes(&mut entropy);

        let msg_scalar = Scalar::<C>::from_be_bytes_reduced(msg_digest.finalize_fixed());
        let k = rfc6979_generate_k::<C, D>(&self.inner, &msg_scalar, &entropy);
        Ok(self.inner.try_sign_prehashed(**k, msg_scalar)?.0)
    }
}

impl<C> RandomizedSigner<Signature<C>> for SigningKey<C>
where
    Self: RandomizedDigestSigner<C::Digest, Signature<C>>,
    C: PrimeCurve + ProjectiveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign_with_rng(&self, rng: impl CryptoRng + RngCore, msg: &[u8]) -> Result<Signature<C>> {
        self.try_sign_digest_with_rng(rng, C::Digest::new().chain(msg))
    }
}

impl<C> From<NonZeroScalar<C>> for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_scalar: NonZeroScalar<C>) -> Self {
        Self {
            inner: secret_scalar,
        }
    }
}

impl<C> TryFrom<&[u8]> for SigningKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

#[cfg(feature = "verify")]
impl<C> From<&SigningKey<C>> for VerifyingKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(signing_key: &SigningKey<C>) -> VerifyingKey<C> {
        signing_key.verifying_key()
    }
}

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
impl<C> TryFrom<pkcs8::PrivateKeyInfo<'_>> for SigningKey<C>
where
    C: PrimeCurve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: sec1::ModulusSize,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfo<'_>) -> pkcs8::Result<Self> {
        SecretKey::try_from(private_key_info).map(Into::into)
    }
}

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
impl<C> DecodePrivateKey for SigningKey<C>
where
    C: PrimeCurve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: sec1::ModulusSize,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<C> FromStr for SigningKey<C>
where
    C: PrimeCurve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: sec1::ModulusSize,
    Scalar<C>: Invert<Output = Scalar<C>> + Reduce<C::UInt> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_pkcs8_pem(s).map_err(|_| Error::new())
    }
}
