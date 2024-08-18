//! ECDSA verifying: checking signatures are authentic using a [`VerifyingKey`].

use crate::{
    hazmat::{self, bits2field, DigestPrimitive},
    EcdsaCurve, Error, Result, Signature, SignatureSize,
};
use core::{cmp::Ordering, fmt::Debug};
use elliptic_curve::{
    array::ArraySize,
    point::PointCompression,
    scalar::IsHigh,
    sec1::{self, CompressedPoint, EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, ProjectivePoint, PublicKey,
};
use signature::{
    digest::{Digest, FixedOutput},
    hazmat::PrehashVerifier,
    DigestVerifier, Verifier,
};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "der")]
use {crate::der, core::ops::Add};

#[cfg(feature = "pem")]
use {core::str::FromStr, elliptic_curve::pkcs8::DecodePublicKey};

#[cfg(feature = "pkcs8")]
use elliptic_curve::pkcs8::{
    self,
    der::AnyRef,
    spki::{
        self, AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier,
    },
    AssociatedOid, ObjectIdentifier,
};

#[cfg(feature = "sha2")]
use {
    crate::{
        SignatureWithOid, ECDSA_SHA224_OID, ECDSA_SHA256_OID, ECDSA_SHA384_OID, ECDSA_SHA512_OID,
    },
    sha2::{Sha224, Sha256, Sha384, Sha512},
};

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
use elliptic_curve::pkcs8::EncodePublicKey;

#[cfg(all(feature = "pem", feature = "serde"))]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// ECDSA public key used for verifying signatures. Generic over prime order
/// elliptic curves (e.g. NIST P-curves).
///
/// Requires an [`elliptic_curve::CurveArithmetic`] impl on the curve.
///
/// ## Usage
///
/// The [`signature`] crate defines the following traits which are the
/// primary API for verifying:
///
/// - [`Verifier`]: verify a message against a provided key and signature
/// - [`DigestVerifier`]: verify a message [`Digest`] against a provided key and signature
/// - [`PrehashVerifier`]: verify the low-level raw output bytes of a message digest
///
/// See the [`p256` crate](https://docs.rs/p256/latest/p256/ecdsa/index.html)
/// for examples of using this type with a concrete elliptic curve.
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, it provides support for
/// serializing and deserializing ECDSA signatures using the `Serialize` and
/// `Deserialize` traits.
///
/// The serialization leverages the encoding used by the [`PublicKey`] type,
/// which is a binary-oriented ASN.1 DER encoding.
#[derive(Clone, Debug)]
pub struct VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
{
    pub(crate) inner: PublicKey<C>,
}

impl<C> VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    /// Initialize [`VerifyingKey`] from a SEC1-encoded public key.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        PublicKey::from_sec1_bytes(bytes)
            .map(|pk| Self { inner: pk })
            .map_err(|_| Error::new())
    }

    /// Initialize [`VerifyingKey`] from an affine point.
    ///
    /// Returns an [`Error`] if the given affine point is the additive identity
    /// (a.k.a. point at infinity).
    pub fn from_affine(affine: AffinePoint<C>) -> Result<Self> {
        Ok(Self {
            inner: PublicKey::from_affine(affine).map_err(|_| Error::new())?,
        })
    }

    /// Initialize [`VerifyingKey`] from an [`EncodedPoint`].
    pub fn from_encoded_point(public_key: &EncodedPoint<C>) -> Result<Self> {
        Option::from(PublicKey::<C>::from_encoded_point(public_key))
            .map(|public_key| Self { inner: public_key })
            .ok_or_else(Error::new)
    }

    /// Serialize this [`VerifyingKey`] as a SEC1 [`EncodedPoint`], optionally
    /// applying point compression.
    pub fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        self.inner.to_encoded_point(compress)
    }

    /// Convert this [`VerifyingKey`] into the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
    /// (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    #[cfg(feature = "alloc")]
    pub fn to_sec1_bytes(&self) -> Box<[u8]>
    where
        C: PointCompression,
    {
        self.inner.to_sec1_bytes()
    }

    /// Borrow the inner [`AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &AffinePoint<C> {
        self.inner.as_affine()
    }
}

//
// `*Verifier` trait impls
//

impl<C, D> DigestVerifier<D, Signature<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    D: Digest + FixedOutput,
    SignatureSize<C>: ArraySize,
{
    fn verify_digest(&self, msg_digest: D, signature: &Signature<C>) -> Result<()> {
        self.verify_prehash(&msg_digest.finalize(), signature)
    }
}

impl<C> PrehashVerifier<Signature<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    SignatureSize<C>: ArraySize,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature<C>) -> Result<()> {
        if C::NORMALIZE_S && signature.s().is_high().into() {
            return Err(Error::new());
        }

        hazmat::verify_prehashed::<C>(
            &ProjectivePoint::<C>::from(*self.inner.as_affine()),
            &bits2field::<C>(prehash)?,
            signature,
        )
    }
}

impl<C> Verifier<Signature<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic + DigestPrimitive,
    SignatureSize<C>: ArraySize,
{
    fn verify(&self, msg: &[u8], signature: &Signature<C>) -> Result<()> {
        self.verify_digest(C::Digest::new_with_prefix(msg), signature)
    }
}

#[cfg(feature = "sha2")]
impl<C> Verifier<SignatureWithOid<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic + DigestPrimitive,
    SignatureSize<C>: ArraySize,
{
    fn verify(&self, msg: &[u8], sig: &SignatureWithOid<C>) -> Result<()> {
        match sig.oid() {
            ECDSA_SHA224_OID => self.verify_prehash(&Sha224::digest(msg), sig.signature()),
            ECDSA_SHA256_OID => self.verify_prehash(&Sha256::digest(msg), sig.signature()),
            ECDSA_SHA384_OID => self.verify_prehash(&Sha384::digest(msg), sig.signature()),
            ECDSA_SHA512_OID => self.verify_prehash(&Sha512::digest(msg), sig.signature()),
            _ => Err(Error::new()),
        }
    }
}

#[cfg(feature = "der")]
impl<C, D> DigestVerifier<D, der::Signature<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    D: Digest + FixedOutput,
    SignatureSize<C>: ArraySize,
    der::MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArraySize,
{
    fn verify_digest(&self, msg_digest: D, signature: &der::Signature<C>) -> Result<()> {
        let signature = Signature::<C>::try_from(signature.clone())?;
        DigestVerifier::<D, Signature<C>>::verify_digest(self, msg_digest, &signature)
    }
}

#[cfg(feature = "der")]
impl<C> PrehashVerifier<der::Signature<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    SignatureSize<C>: ArraySize,
    der::MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArraySize,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &der::Signature<C>) -> Result<()> {
        let signature = Signature::<C>::try_from(signature.clone())?;
        PrehashVerifier::<Signature<C>>::verify_prehash(self, prehash, &signature)
    }
}

#[cfg(feature = "der")]
impl<C> Verifier<der::Signature<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic + DigestPrimitive,
    SignatureSize<C>: ArraySize,
    der::MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArraySize,
{
    fn verify(&self, msg: &[u8], signature: &der::Signature<C>) -> Result<()> {
        let signature = Signature::<C>::try_from(signature.clone())?;
        Verifier::<Signature<C>>::verify(self, msg, &signature)
    }
}

//
// Other trait impls
//

impl<C> AsRef<AffinePoint<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn as_ref(&self) -> &AffinePoint<C> {
        self.as_affine()
    }
}

impl<C> Copy for VerifyingKey<C> where C: EcdsaCurve + CurveArithmetic {}

impl<C> From<VerifyingKey<C>> for CompressedPoint<C>
where
    C: EcdsaCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(verifying_key: VerifyingKey<C>) -> CompressedPoint<C> {
        verifying_key.inner.into()
    }
}

impl<C> From<&VerifyingKey<C>> for CompressedPoint<C>
where
    C: EcdsaCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(verifying_key: &VerifyingKey<C>) -> CompressedPoint<C> {
        verifying_key.inner.into()
    }
}

impl<C> From<VerifyingKey<C>> for EncodedPoint<C>
where
    C: EcdsaCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(verifying_key: VerifyingKey<C>) -> EncodedPoint<C> {
        verifying_key.inner.into()
    }
}

impl<C> From<&VerifyingKey<C>> for EncodedPoint<C>
where
    C: EcdsaCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(verifying_key: &VerifyingKey<C>) -> EncodedPoint<C> {
        verifying_key.inner.into()
    }
}

impl<C> Eq for VerifyingKey<C> where C: EcdsaCurve + CurveArithmetic {}

impl<C> PartialEq for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl<C> From<PublicKey<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
{
    fn from(public_key: PublicKey<C>) -> VerifyingKey<C> {
        VerifyingKey { inner: public_key }
    }
}

impl<C> From<&PublicKey<C>> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
{
    fn from(public_key: &PublicKey<C>) -> VerifyingKey<C> {
        (*public_key).into()
    }
}

impl<C> From<VerifyingKey<C>> for PublicKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
{
    fn from(verifying_key: VerifyingKey<C>) -> PublicKey<C> {
        verifying_key.inner
    }
}

impl<C> From<&VerifyingKey<C>> for PublicKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
{
    fn from(verifying_key: &VerifyingKey<C>) -> PublicKey<C> {
        (*verifying_key).into()
    }
}

impl<C> PartialOrd for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C> Ord for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl<C> TryFrom<&[u8]> for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_sec1_bytes(bytes)
    }
}

#[cfg(feature = "pkcs8")]
impl<C> AssociatedAlgorithmIdentifier for VerifyingKey<C>
where
    C: EcdsaCurve + AssociatedOid + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Params = ObjectIdentifier;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<ObjectIdentifier> =
        PublicKey::<C>::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "pkcs8")]
impl<C> SignatureAlgorithmIdentifier for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    Signature<C>: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<C>::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "pkcs8")]
impl<C> TryFrom<pkcs8::SubjectPublicKeyInfoRef<'_>> for VerifyingKey<C>
where
    C: EcdsaCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Error = spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        PublicKey::try_from(spki).map(|inner| Self { inner })
    }
}

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
impl<C> EncodePublicKey for VerifyingKey<C>
where
    C: EcdsaCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn to_public_key_der(&self) -> spki::Result<pkcs8::Document> {
        self.inner.to_public_key_der()
    }
}

#[cfg(feature = "pem")]
impl<C> FromStr for VerifyingKey<C>
where
    C: EcdsaCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_public_key_pem(s).map_err(|_| Error::new())
    }
}

#[cfg(all(feature = "pem", feature = "serde"))]
impl<C> Serialize for VerifyingKey<C>
where
    C: EcdsaCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(all(feature = "pem", feature = "serde"))]
impl<'de, C> Deserialize<'de> for VerifyingKey<C>
where
    C: EcdsaCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        PublicKey::<C>::deserialize(deserializer).map(Into::into)
    }
}
