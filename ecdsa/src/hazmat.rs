//! Low-level ECDSA primitives.
//!
//! # ⚠️ Warning: Hazmat!
//!
//! YOU PROBABLY DON'T WANT TO USE THESE!
//!
//! These primitives are easy-to-misuse low-level interfaces.
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
        ops::{Invert, LinearCombination, Reduce},
        AffineArithmetic, AffineXCoordinate, Field, FieldBytes, Group, ProjectiveArithmetic,
        ProjectivePoint, Scalar, ScalarArithmetic,
    },
};

#[cfg(feature = "digest")]
use {
    elliptic_curve::FieldSize,
    signature::{digest::Digest, PrehashSignature},
};

#[cfg(any(feature = "arithmetic", feature = "digest"))]
use crate::{
    elliptic_curve::{generic_array::ArrayLength, PrimeCurve},
    Signature,
};

#[cfg(all(feature = "sign"))]
use {
    elliptic_curve::{ff::PrimeField, zeroize::Zeroizing, NonZeroScalar, ScalarCore},
    signature::digest::{BlockInput, FixedOutput, Reset, Update},
};

/// Try to sign the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on a type with access to the
/// secret scalar via `&self`, such as particular curve's `Scalar` type.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait SignPrimitive<C>: Field + Into<FieldBytes<C>> + Reduce<C::UInt> + Sized
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
        K: Borrow<Self> + Invert<Output = Self>,
    {
        if k.borrow().is_zero().into() {
            return Err(Error::new());
        }

        // Compute scalar inversion of 𝑘
        let k_inv = Option::<Scalar<C>>::from(k.invert()).ok_or_else(Error::new)?;

        // Compute 𝐑 = 𝑘×𝑮
        let R = (C::ProjectivePoint::generator() * k.borrow()).to_affine();

        // Lift x-coordinate of 𝐑 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let r = Self::from_be_bytes_reduced(R.x());

        // Compute `s` as a signature over `r` and `z`.
        let s = k_inv * (z + (r * self));

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
pub trait VerifyPrimitive<C>: AffineXCoordinate<C> + Copy + Sized
where
    C: PrimeCurve + AffineArithmetic<AffinePoint = Self> + ProjectiveArithmetic,
    Scalar<C>: Reduce<C::UInt>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Verify the prehashed message against the provided signature
    ///
    /// Accepts the following arguments:
    ///
    /// - `z`: prehashed message to be verified
    /// - `sig`: signature to be verified against the key and message
    fn verify_prehashed(&self, z: Scalar<C>, sig: &Signature<C>) -> Result<()> {
        let (r, s) = sig.split_scalars();
        let s_inv = Option::<Scalar<C>>::from(s.invert()).ok_or_else(Error::new)?;
        let u1 = z * s_inv;
        let u2 = *r * s_inv;
        let x = ProjectivePoint::<C>::lincomb(
            &ProjectivePoint::<C>::generator(),
            &u1,
            &ProjectivePoint::<C>::from(*self),
            &u2,
        )
        .to_affine()
        .x();

        if Scalar::<C>::from_be_bytes_reduced(x) == *r {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
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

/// Deterministically compute ECDSA ephemeral scalar `k` using the method
/// described in RFC6979.
///
/// Accepts the following parameters:
/// - `x`: secret key
/// - `z`: message scalar (i.e. message digest reduced mod p)
/// - `ad`: optional additional data, e.g. added entropy from an RNG
#[cfg(all(feature = "sign"))]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub fn rfc6979_generate_k<C, D>(
    x: &NonZeroScalar<C>,
    z: &Scalar<C>,
    ad: &[u8],
) -> Zeroizing<NonZeroScalar<C>>
where
    C: PrimeCurve + ProjectiveArithmetic,
    D: FixedOutput<OutputSize = FieldSize<C>> + BlockInput + Clone + Default + Reset + Update,
{
    // TODO(tarcieri): avoid this conversion
    let x = Zeroizing::new(ScalarCore::<C>::from(x));
    let k = rfc6979::generate_k::<D, C::UInt>(x.as_uint(), &C::ORDER, &z.to_repr(), ad);
    Zeroizing::new(NonZeroScalar::<C>::from_uint(*k).unwrap())
}
