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
        ff::PrimeField, ops::Invert, FieldBytes, ProjectiveArithmetic, Scalar, ScalarArithmetic,
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

#[cfg(docsrs)]
use elliptic_curve::ops::Reduce;

/// Multiplication operation performed on the ECDSA `k` scalar.
///
/// This trait provides a minimum integration needed for a curve implementation
/// to leverage a generic implementation of ECDSA. It's designed to make it
/// possible to encapsulate elements of the base field from the public API,
/// exposing only the functionality needed to compute ECDSA signatures.
///
/// When implemented on a particular curve's `Scalar` type, it will receive a
/// blanket impl of [`SignPrimitive`], which contains the core ECDSA signature
/// algorithm.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait MulBaseReduced: PrimeField {
    /// Perform 𝑘×𝑮 fixed-base scalar multiplication, lifting the x-coordinate
    /// of the resulting `AffinePoint` into an integer, and then reduce it into
    /// an element of the scalar field.
    ///
    /// The implementation will look roughly like the following:
    ///
    /// ```ignore
    /// let x = (C::ProjectivePoint::generator() * k).to_affine().x;
    /// Scalar::from_be_bytes_reduced(x.to_bytes())
    /// ```
    fn mul_base_reduced(&self) -> Self;
}

/// Try to sign the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on a type with access
/// to the secret scalar via `&self`, such as particular curve's `Scalar` type,
/// or potentially a key handle to a hardware device.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait SignPrimitive<C>
where
    C: PrimeCurve + ScalarArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Try to sign the prehashed message.
    ///
    /// Accepts the following arguments:
    ///
    /// - `ephemeral_scalar`: ECDSA `k` value. MUST BE UNIFORMLY RANDOM!!!
    /// - `hashed_msg`: scalar computed from a hashed message digest to be signed.
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
    fn try_sign_prehashed<K>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &Scalar<C>,
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        K: Borrow<Scalar<C>> + Invert<Output = Scalar<C>>;
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

/// Generic implementation of the ECDSA signature algorithm for curves whose
/// `C::Scalar` type impls the [`MulBaseReduced`] trait.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C, S> SignPrimitive<C> for S
where
    C: PrimeCurve + ScalarArithmetic<Scalar = S>,
    S: MulBaseReduced + Into<FieldBytes<C>>,
    SignatureSize<C>: ArrayLength<u8>,
{
    #[allow(clippy::many_single_char_names)]
    fn try_sign_prehashed<K>(&self, k: &K, z: &S) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        K: Borrow<S> + Invert<Output = S>,
    {
        if k.borrow().is_zero().into() {
            return Err(Error::new());
        }

        let k_inverse = Option::<S>::from(k.invert()).ok_or_else(Error::new)?;

        // Compute 𝐑 = 𝑘×𝑮, then lift x-coordinate of 𝐑 (element of base field)
        // into a serialized big integer, then reduce it into an element of the
        // scalar field.
        let r = k.borrow().mul_base_reduced();

        // Compute `s` as a signature over `r` and `z`.
        // TODO(tarcieri): avoid making a copy of `z` with better reference-based bounds
        let s = k_inverse * (*z + (r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        // TODO(tarcieri): support for computing recovery ID
        Ok((Signature::from_scalars(r, s)?, None))
    }
}
