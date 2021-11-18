//! Low-level ECDSA primitives.
//!
//! # ⚠️ Warning: Hazmat!
//!
//! YOU PROBABLY DON'T WANT TO USE THESE!
//!
//! These primitives are easy-to-misuse low-level interfaces intended to be
//! implemented by elliptic curve crates and consumed only by this crate!
//!
//! If you are an end user / non-expert in cryptography, do not use these!
//! Failure to use them correctly can lead to catastrophic failures including
//! FULL PRIVATE KEY RECOVERY!

#[cfg(feature = "arithmetic")]
use {
    crate::{Error, RecoveryId, Result, SignatureSize},
    core::borrow::Borrow,
    elliptic_curve::{
        group::Curve as _,
        ops::{Invert, Reduce},
        AffineXCoordinate, Field, FieldBytes, Group, ProjectiveArithmetic, Scalar,
        ScalarArithmetic,
    },
};

#[cfg(feature = "digest")]
use {
    crate::signature::{digest::Digest, PrehashSignature},
    elliptic_curve::FieldSize,
};

#[cfg(any(feature = "arithmetic", feature = "digest"))]
use crate::{
    elliptic_curve::{generic_array::ArrayLength, PrimeCurve},
    Signature,
};

/// Try to sign the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on a type with access to the
/// secret scalar via `&self`, such as particular curve's `Scalar` type.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait SignPrimitive<C>: Field + Sized
where
    C: PrimeCurve + ProjectiveArithmetic + ScalarArithmetic<Scalar = Self>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Try to sign the prehashed message.
    ///
    /// Accepts the following arguments:
    ///
    /// - `k`: ephemeral scalar value. MUST BE UNIFORMLY RANDOM!!!
    /// - `z`: scalar computed from a hashed message digest to be signed.
    ///   MUST BE OUTPUT OF A CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!!!
    ///
    /// # Computing the `hashed_msg` scalar
    ///
    /// To compute a [`Scalar`] from a message digest, use the [`Reduce`] trait
    /// on the computed digest, e.g. `Scalar::from_be_bytes_reduced`.
    ///
    /// # Returns
    ///
    /// ECDSA [`Signature`] and, when possible/desired, a [`RecoveryId`]
    /// which can be used to recover the verifying key for a given signature.
    #[allow(non_snake_case)]
    fn try_sign_prehashed<K>(
        &self,
        k: K,
        z: Scalar<C>,
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        Self: Into<FieldBytes<C>> + Reduce<C::UInt>,
        K: Borrow<Self> + Invert<Output = Self>,
    {
        if k.borrow().is_zero().into() {
            return Err(Error::new());
        }

        // Compute scalar inversion of 𝑘
        let k_inverse = Option::<Scalar<C>>::from(k.invert()).ok_or_else(Error::new)?;

        // Compute 𝐑 = 𝑘×𝑮
        let R = (C::ProjectivePoint::generator() * k.borrow()).to_affine();

        // Lift x-coordinate of 𝐑 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let r = Self::from_be_bytes_reduced(R.x());

        // Compute `s` as a signature over `r` and `z`.
        let s = k_inverse * (z + (r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        // TODO(tarcieri): support for computing recovery ID
        Ok((Signature::from_scalars(r, s)?, None))
    }
}

/// Verify the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on type which can access
/// the affine point represeting the public key via `&self`, such as a
/// particular curve's `AffinePoint` type.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait VerifyPrimitive<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Verify the prehashed message against the provided signature
    ///
    /// Accepts the following arguments:
    ///
    /// - `hashed_msg`: prehashed message to be verified
    /// - `signature`: signature to be verified against the key and message
    fn verify_prehashed(&self, hashed_msg: &Scalar<C>, signature: &Signature<C>) -> Result<()>;
}

/// Bind a preferred [`Digest`] algorithm to an elliptic curve type.
///
/// Generally there is a preferred variety of the SHA-2 family used with ECDSA
/// for a particular elliptic curve.
///
/// This trait can be used to specify it, and with it receive a blanket impl of
/// [`PrehashSignature`], used by [`signature_derive`][1]) for the [`Signature`]
/// type for a particular elliptic curve.
///
/// [1]: https://github.com/RustCrypto/traits/tree/master/signature/derive
#[cfg(feature = "digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
pub trait DigestPrimitive: PrimeCurve {
    /// Preferred digest to use when computing ECDSA signatures for this
    /// elliptic curve. This should be a member of the SHA-2 family.
    type Digest: Digest;
}

#[cfg(feature = "digest")]
impl<C> PrehashSignature for Signature<C>
where
    C: DigestPrimitive,
    <FieldSize<C> as core::ops::Add>::Output: ArrayLength<u8>,
{
    type Digest = C::Digest;
}
