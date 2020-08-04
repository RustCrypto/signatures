//! ECDSA verifier. Generic over elliptic curves.
//!
//! Requires an [`elliptic_curve::Arithmetic`] impl on the curve, and a
//! [`VerifyPrimitive`] impl on its associated `AffinePoint` type.

use crate::{
    hazmat::{DigestPrimitive, VerifyPrimitive},
    Error, Signature, SignatureSize,
};
use core::ops::Add;
use elliptic_curve::{
    consts::U1,
    generic_array::ArrayLength,
    weierstrass::{
        point::{CompressedPointSize, UncompressedPointSize},
        public_key::{FromPublicKey, PublicKey},
        Curve,
    },
    Arithmetic,
};
use signature::{digest::Digest, DigestVerifier};

/// ECDSA verifier
pub struct Verifier<C: Curve + Arithmetic> {
    public_key: C::AffinePoint,
}

impl<C> Verifier<C>
where
    C: Curve + Arithmetic,
    C::AffinePoint: VerifyPrimitive<C> + FromPublicKey<C>,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Create a new verifier
    pub fn new(public_key: &PublicKey<C>) -> Result<Self, Error> {
        let affine_point = C::AffinePoint::from_public_key(public_key);

        if affine_point.is_some().into() {
            Ok(Self {
                public_key: affine_point.unwrap(),
            })
        } else {
            Err(Error::new())
        }
    }
}

impl<C, D> DigestVerifier<D, Signature<C>> for Verifier<C>
where
    C: Curve + Arithmetic,
    D: Digest<OutputSize = C::ElementSize>,
    C::AffinePoint: VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify_digest(&self, digest: D, signature: &Signature<C>) -> Result<(), Error> {
        self.public_key
            .verify_prehashed(&digest.finalize(), signature)
    }
}

impl<C> signature::Verifier<Signature<C>> for Verifier<C>
where
    C: Curve + Arithmetic + DigestPrimitive,
    C::AffinePoint: VerifyPrimitive<C>,
    C::Digest: Digest<OutputSize = C::ElementSize>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify(&self, msg: &[u8], signature: &Signature<C>) -> Result<(), Error> {
        self.verify_digest(C::Digest::new().chain(msg), signature)
    }
}
