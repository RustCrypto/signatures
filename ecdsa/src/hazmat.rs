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
use elliptic_curve::{generic_array::ArrayLength, weierstrass::Curve, Error, ScalarBytes};

/// Try to sign the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on a type with access
/// to the secret scalar via `&self`, such as particular curve's `Scalar` type,
/// or potentially a key handle to a hardware device.
pub trait SignPrimitive<C>
where
    C: Curve,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Scalar type
    // TODO(tarcieri): add bounds that support generation/conversion from bytes
    type Scalar;

    /// Try to sign the prehashed message.
    ///
    /// Accepts the following arguments:
    ///
    /// - `ephemeral_scalar`: ECDSA `k` value (MUST BE UNIFORMLY RANDOM!!!)
    /// - `masking_scalar`: optional blinding factor for sidechannel resistance
    /// - `hashed_msg`: prehashed message to be signed
    fn try_sign_prehashed(
        &self,
        ephemeral_scalar: Self::Scalar,
        masking_scalar: Option<Self::Scalar>,
        hashed_msg: &ScalarBytes<C::ScalarSize>,
    ) -> Result<Signature<C>, Error>;
}

/// Verify the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on type which can access
/// the affine point represeting the public key via `&self`, such as a
/// particular curve's `AffinePoint` type.
pub trait VerifyPrimitive<C>
where
    C: Curve,
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
        hashed_msg: &ScalarBytes<C::ScalarSize>,
        signature: &Signature<C>,
    ) -> Result<(), Error>;
}
