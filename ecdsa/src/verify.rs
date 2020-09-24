//! ECDSA verification key (i.e. public key). Generic over elliptic curves.
//!
//! Requires an [`elliptic_curve::ProjectiveArithmetic`] impl on the curve, and a
//! [`VerifyPrimitive`] impl on its associated `AffinePoint` type.

use crate::{
    hazmat::{DigestPrimitive, VerifyPrimitive},
    Error, Signature, SignatureSize,
};
use core::{fmt::Debug, ops::Add};
use elliptic_curve::{
    consts::U1,
    ff::PrimeField,
    generic_array::ArrayLength,
    point::AffinePoint,
    sec1::{
        EncodedPoint, FromEncodedPoint, ToEncodedPoint, UncompressedPointSize, UntaggedPointSize,
    },
    weierstrass::{point, Curve},
    FieldBytes, FromDigest, ProjectiveArithmetic, Scalar,
};
use signature::{digest::Digest, DigestVerifier};

/// ECDSA verify key
#[derive(Clone, Debug)]
pub struct VerifyKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug,
{
    pub(crate) public_key: AffinePoint<C>,
}

impl<C> VerifyKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + FromDigest<C>,
    AffinePoint<C>: Clone + Debug + VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Initialize [`VerifyKey`] from a SEC1-encoded public key.
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        EncodedPoint::from_bytes(bytes)
            .map_err(|_| Error::new())
            .and_then(|point| Self::from_encoded_point(&point))
    }

    /// Initialize [`VerifyKey`] from an [`EncodedPoint`].
    pub fn from_encoded_point(public_key: &EncodedPoint<C>) -> Result<Self, Error> {
        let affine_point = AffinePoint::<C>::from_encoded_point(public_key);

        if affine_point.is_some().into() {
            Ok(Self {
                public_key: affine_point.unwrap(),
            })
        } else {
            Err(Error::new())
        }
    }

    /// Serialize this [`VerifyKey`] as a SEC1 [`EncodedPoint`], optionally
    /// applying point compression.
    pub fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        self.public_key.to_encoded_point(compress)
    }
}

impl<C, D> DigestVerifier<D, Signature<C>> for VerifyKey<C>
where
    C: Curve + ProjectiveArithmetic,
    D: Digest<OutputSize = C::FieldSize>,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + FromDigest<C>,
    AffinePoint<C>: Clone + Debug + VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify_digest(&self, digest: D, signature: &Signature<C>) -> Result<(), Error> {
        self.public_key
            .verify_prehashed(&Scalar::<C>::from_digest(digest), signature)
    }
}

impl<C> signature::Verifier<Signature<C>> for VerifyKey<C>
where
    C: Curve + ProjectiveArithmetic + DigestPrimitive,
    C::Digest: Digest<OutputSize = C::FieldSize>,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + FromDigest<C>,
    AffinePoint<C>: Clone + Debug + VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify(&self, msg: &[u8], signature: &Signature<C>) -> Result<(), Error> {
        self.verify_digest(C::Digest::new().chain(msg), signature)
    }
}

impl<C> From<&VerifyKey<C>> for EncodedPoint<C>
where
    C: Curve + ProjectiveArithmetic + point::Compression,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + FromDigest<C>,
    AffinePoint<C>: Clone + Debug + VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from(verify_key: &VerifyKey<C>) -> EncodedPoint<C> {
        verify_key.to_encoded_point(C::COMPRESS_POINTS)
    }
}

impl<C> PartialEq for VerifyKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + FromDigest<C>,
    AffinePoint<C>: Clone + Debug + VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn eq(&self, other: &Self) -> bool {
        self.to_encoded_point(false) == other.to_encoded_point(false)
    }
}

impl<C> Copy for VerifyKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Copy + Clone + Debug,
{
}

impl<C> Eq for VerifyKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + FromDigest<C>,
    AffinePoint<C>: Clone + Debug + VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
{
}
