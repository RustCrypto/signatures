//! ECDSA signing key.

// TODO(tarcieri): support for hardware crypto accelerators

use crate::{
    hazmat::{DigestPrimitive, FromDigest, SignPrimitive},
    rfc6979, Error, Signature, SignatureSize,
};
use elliptic_curve::{
    generic_array::ArrayLength, group::ff::PrimeField, ops::Invert, weierstrass::Curve,
    zeroize::Zeroize, FieldBytes, FieldSize, NonZeroScalar, ProjectiveArithmetic, Scalar,
    SecretKey,
};
use signature::{
    digest::{BlockInput, Digest, FixedOutput, Reset, Update},
    rand_core::{CryptoRng, RngCore},
    DigestSigner, RandomizedDigestSigner, RandomizedSigner,
};

#[cfg(feature = "verify")]
use {
    crate::verify::VerifyingKey,
    elliptic_curve::{AffinePoint, PublicKey},
};

#[cfg(feature = "pkcs8")]
use crate::elliptic_curve::{
    consts::U1,
    ops::Add,
    pkcs8::{self, FromPrivateKey},
    sec1::{FromEncodedPoint, ToEncodedPoint, UncompressedPointSize, UntaggedPointSize},
    AlgorithmParameters,
};

#[cfg(feature = "pem")]
use core::str::FromStr;

/// ECDSA signing key. Generic over elliptic curves.
///
/// Requires an [`elliptic_curve::ProjectiveArithmetic`] impl on the curve, and a
/// [`SignPrimitive`] impl on its associated `Scalar` type.
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub struct SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    inner: NonZeroScalar<C>,
}

impl<C> SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Generate a cryptographically random [`SigningKey`].
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            inner: NonZeroScalar::random(rng),
        }
    }

    /// Initialize signing key from a raw scalar serialized as a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let inner = SecretKey::from_bytes(bytes)
            .map(|sk| sk.to_secret_scalar())
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

impl<C> Drop for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<C> From<SecretKey<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_key: SecretKey<C>) -> Self {
        Self::from(&secret_key)
    }
}

impl<C> From<&SecretKey<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_key: &SecretKey<C>) -> Self {
        Self {
            inner: secret_key.to_secret_scalar(),
        }
    }
}

impl<C, D> DigestSigner<D, Signature<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    D: FixedOutput<OutputSize = FieldSize<C>> + BlockInput + Clone + Default + Reset + Update,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Sign message prehash using a deterministic ephemeral scalar (`k`)
    /// computed using the algorithm described in RFC 6979 (Section 3.2):
    /// <https://tools.ietf.org/html/rfc6979#section-3>
    fn try_sign_digest(&self, digest: D) -> Result<Signature<C>, Error> {
        let k = rfc6979::generate_k(&self.inner, digest.clone(), &[]);
        let msg_scalar = Scalar::<C>::from_digest(digest);
        self.inner.try_sign_prehashed(&**k, &msg_scalar)
    }
}

impl<C> signature::Signer<Signature<C>> for SigningKey<C>
where
    Self: DigestSigner<C::Digest, Signature<C>>,
    C: Curve + ProjectiveArithmetic + DigestPrimitive,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, signature::Error> {
        self.try_sign_digest(C::Digest::new().chain(msg))
    }
}

impl<C, D> RandomizedDigestSigner<D, Signature<C>> for SigningKey<C>
where
    C: Curve + ProjectiveArithmetic,
    D: FixedOutput<OutputSize = FieldSize<C>> + BlockInput + Clone + Default + Reset + Update,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
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

        let k = rfc6979::generate_k(&self.inner, digest.clone(), &added_entropy);
        let msg_scalar = Scalar::<C>::from_digest(digest);
        self.inner.try_sign_prehashed(&**k, &msg_scalar)
    }
}

impl<C> RandomizedSigner<Signature<C>> for SigningKey<C>
where
    Self: RandomizedDigestSigner<C::Digest, Signature<C>>,
    C: Curve + ProjectiveArithmetic + DigestPrimitive,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
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
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(secret_scalar: NonZeroScalar<C>) -> Self {
        Self {
            inner: secret_scalar,
        }
    }
}

#[cfg(feature = "verify")]
impl<C> From<&SigningKey<C>> for VerifyingKey<C>
where
    C: Curve + ProjectiveArithmetic,

    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(signing_key: &SigningKey<C>) -> VerifyingKey<C> {
        signing_key.verifying_key()
    }
}

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
impl<C> FromPrivateKey for SigningKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from_pkcs8_private_key_info(
        private_key_info: pkcs8::PrivateKeyInfo<'_>,
    ) -> pkcs8::Result<Self> {
        SecretKey::from_pkcs8_private_key_info(private_key_info).map(Into::into)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<C> FromStr for SigningKey<C>
where
    C: Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    Scalar<C>: FromDigest<C> + Invert<Output = Scalar<C>> + SignPrimitive<C> + Zeroize,
    SignatureSize<C>: ArrayLength<u8>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_pkcs8_pem(s).map_err(|_| Error::new())
    }
}
