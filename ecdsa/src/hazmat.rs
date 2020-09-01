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

use crate::{Signature, SignatureSize};
use core::borrow::Borrow;
use elliptic_curve::{generic_array::ArrayLength, ops::Invert, weierstrass::Curve, Arithmetic};
use signature::Error;

#[cfg(feature = "digest")]
use signature::{digest::Digest, PrehashSignature};

/// Try to sign the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on a type with access
/// to the secret scalar via `&self`, such as particular curve's `Scalar` type,
/// or potentially a key handle to a hardware device.
pub trait SignPrimitive<C>
where
    C: Curve + Arithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Try to sign the prehashed message.
    ///
    /// Accepts the following arguments:
    ///
    /// - `ephemeral_scalar`: ECDSA `k` value. MUST BE UNIFORMLY RANDOM!!!
    /// - `hashed_msg`: scalar computed from a hashed message digest to be signed.
    ///   MUST BE OUTPUT OF A CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!!!
    fn try_sign_prehashed<K: Borrow<C::Scalar> + Invert<Output = C::Scalar>>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &C::Scalar,
    ) -> Result<Signature<C>, Error>;
}

/// [`SignPrimitive`] for signature implementations that can provide public key
/// recovery implementation.
pub trait RecoverableSignPrimitive<C>
where
    C: Curve + Arithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Type for recoverable signatures
    type RecoverableSignature: signature::Signature + Into<Signature<C>>;

    /// Try to sign the prehashed message.
    ///
    /// Accepts the same arguments as [`SignPrimitive::try_sign_prehashed`]
    /// but returns a boolean flag which indicates whether or not the
    /// y-coordinate of the computed 𝐑 = 𝑘×𝑮 point is odd, which can be
    /// incorporated into recoverable signatures.
    fn try_sign_recoverable_prehashed<K: Borrow<C::Scalar> + Invert<Output = C::Scalar>>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &C::Scalar,
    ) -> Result<Self::RecoverableSignature, Error>;
}

impl<C, T> SignPrimitive<C> for T
where
    C: Curve + Arithmetic,
    T: RecoverableSignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign_prehashed<K: Borrow<C::Scalar> + Invert<Output = C::Scalar>>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &C::Scalar,
    ) -> Result<Signature<C>, Error> {
        self.try_sign_recoverable_prehashed(ephemeral_scalar, hashed_msg)
            .map(Into::into)
    }
}

/// Verify the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on type which can access
/// the affine point represeting the public key via `&self`, such as a
/// particular curve's `AffinePoint` type.
pub trait VerifyPrimitive<C>
where
    C: Curve + Arithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Verify the prehashed message against the provided signature
    ///
    /// Accepts the following arguments:
    ///
    /// - `verify_key`: public key to verify the signature against
    /// - `hashed_msg`: prehashed message to be verified
    /// - `signature`: signature to be verified against the key and message
    fn verify_prehashed(
        &self,
        hashed_msg: &C::Scalar,
        signature: &Signature<C>,
    ) -> Result<(), Error>;
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
pub trait DigestPrimitive: Curve {
    /// Preferred digest to use when computing ECDSA signatures for this
    /// elliptic curve. This should be a member of the SHA-2 family.
    type Digest: Digest;
}

#[cfg(feature = "digest")]
impl<C: DigestPrimitive> PrehashSignature for Signature<C>
where
    <C::ElementSize as core::ops::Add>::Output: ArrayLength<u8>,
{
    type Digest = C::Digest;
}
