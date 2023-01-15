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

use crate::{Error, Result};
use core::cmp;
use elliptic_curve::{bigint::Encoding, FieldBytes, PrimeCurve};

#[cfg(feature = "arithmetic")]
use {
    crate::{RecoveryId, SignatureSize},
    core::borrow::Borrow,
    elliptic_curve::{
        group::Curve as _,
        ops::{Invert, LinearCombination, Reduce},
        subtle::CtOption,
        AffineArithmetic, AffineXCoordinate, Field, Group, ProjectiveArithmetic, ProjectivePoint,
        Scalar, ScalarArithmetic,
    },
};

#[cfg(feature = "digest")]
use {
    elliptic_curve::FieldSize,
    signature::{
        digest::{core_api::BlockSizeUser, Digest, FixedOutputReset},
        PrehashSignature,
    },
};

#[cfg(any(feature = "arithmetic", feature = "digest"))]
use crate::{elliptic_curve::generic_array::ArrayLength, Signature};

#[cfg(all(feature = "arithmetic", feature = "digest"))]
use signature::digest::FixedOutput;

#[cfg(feature = "rfc6979")]
use elliptic_curve::ScalarCore;

/// Try to sign the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on a type with access to the
/// secret scalar via `&self`, such as particular curve's `Scalar` type.
#[cfg(feature = "arithmetic")]
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
    /// - `z`: message digest to be signed. MUST BE OUTPUT OF A CRYPTOGRAPHICALLY
    ///        SECURE DIGEST ALGORITHM!!!
    ///
    /// # Returns
    ///
    /// ECDSA [`Signature`] and, when possible/desired, a [`RecoveryId`]
    /// which can be used to recover the verifying key for a given signature.
    #[allow(non_snake_case)]
    fn try_sign_prehashed<K>(
        &self,
        k: K,
        z: FieldBytes<C>,
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        K: Borrow<Self> + Invert<Output = CtOption<Self>>,
    {
        if k.borrow().is_zero().into() {
            return Err(Error::new());
        }

        let z = Self::from_be_bytes_reduced(z);

        // Compute scalar inversion of 𝑘
        let k_inv = Option::<Scalar<C>>::from(k.invert()).ok_or_else(Error::new)?;

        // Compute 𝑹 = 𝑘×𝑮
        let R = (C::ProjectivePoint::generator() * k.borrow()).to_affine();

        // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let r = Self::from_be_bytes_reduced(R.x());

        // Compute 𝒔 as a signature over 𝒓 and 𝒛.
        let s = k_inv * (z + (r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        // TODO(tarcieri): support for computing recovery ID (RustCrypto/signatures#581)
        Ok((Signature::from_scalars(r, s)?, None))
    }

    /// Try to sign the given message digest deterministically using the method
    /// described in [RFC6979] for computing ECDSA ephemeral scalar `k`.
    ///
    /// Accepts the following parameters:
    /// - `z`: message digest to be signed.
    /// - `ad`: optional additional data, e.g. added entropy from an RNG
    ///
    /// [RFC6979]: https://datatracker.ietf.org/doc/html/rfc6979
    #[cfg(all(feature = "rfc6979"))]
    fn try_sign_prehashed_rfc6979<D>(
        &self,
        z: FieldBytes<C>,
        ad: &[u8],
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        Self: From<ScalarCore<C>>,
        C::UInt: for<'a> From<&'a Self>,
        D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldSize<C>> + FixedOutputReset,
    {
        let x = C::UInt::from(self);
        let k = rfc6979::generate_k::<D, C::UInt>(&x, &C::ORDER, &z, ad);
        let k = Self::from(ScalarCore::<C>::new(*k).unwrap());
        self.try_sign_prehashed(k, z)
    }

    /// Try to sign the given digest instance using the method described in
    /// [RFC6979].
    ///
    /// [RFC6979]: https://datatracker.ietf.org/doc/html/rfc6979
    #[cfg(all(feature = "rfc6979"))]
    fn try_sign_digest_rfc6979<D>(
        &self,
        msg_digest: D,
        ad: &[u8],
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        Self: From<ScalarCore<C>>,
        C::UInt: for<'a> From<&'a Self>,
        D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldSize<C>> + FixedOutputReset,
    {
        self.try_sign_prehashed_rfc6979::<D>(msg_digest.finalize_fixed(), ad)
    }
}

/// Verify the given prehashed message using ECDSA.
///
/// This trait is intended to be implemented on type which can access
/// the affine point represeting the public key via `&self`, such as a
/// particular curve's `AffinePoint` type.
#[cfg(feature = "arithmetic")]
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
    /// - `z`: message digest to be verified. MUST BE OUTPUT OF A
    ///        CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!!!
    /// - `sig`: signature to be verified against the key and message
    fn verify_prehashed(&self, z: FieldBytes<C>, sig: &Signature<C>) -> Result<()> {
        let z = Scalar::<C>::from_be_bytes_reduced(z);
        let (r, s) = sig.split_scalars();
        let s_inv = *s.invert();
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

    /// Verify message digest against the provided signature.
    #[cfg(feature = "digest")]
    fn verify_digest<D>(&self, msg_digest: D, sig: &Signature<C>) -> Result<()>
    where
        D: FixedOutput<OutputSize = FieldSize<C>>,
    {
        self.verify_prehashed(msg_digest.finalize_fixed(), sig)
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
pub trait DigestPrimitive: PrimeCurve {
    /// Preferred digest to use when computing ECDSA signatures for this
    /// elliptic curve. This is typically a member of the SHA-2 family.
    type Digest: BlockSizeUser + Digest + FixedOutputReset;
}

#[cfg(feature = "digest")]
impl<C> PrehashSignature for Signature<C>
where
    C: DigestPrimitive,
    <FieldSize<C> as core::ops::Add>::Output: ArrayLength<u8>,
{
    type Digest = C::Digest;
}

/// Partial implementation of the `bits2int` function as defined in
/// [RFC6979 § 2.3.2] as well as [SEC1] § 2.3.8.
///
/// This is used to convert a message digest whose size may be smaller or
/// larger than the size of the curve's scalar field into a serialized
/// (unreduced) field element.
///
/// [RFC6979 § 2.3.2]: https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.2
/// [SEC1]: https://www.secg.org/sec1-v2.pdf
pub fn bits2field<C: PrimeCurve>(bits: &[u8]) -> Result<FieldBytes<C>> {
    // Minimum allowed bits size is half the field size
    if bits.len() < C::UInt::BYTE_SIZE / 2 {
        return Err(Error::new());
    }

    let mut field_bytes = FieldBytes::<C>::default();

    match bits.len().cmp(&C::UInt::BYTE_SIZE) {
        cmp::Ordering::Equal => field_bytes.copy_from_slice(bits),
        cmp::Ordering::Less => {
            // If bits is smaller than the field size, pad with zeroes on the left
            field_bytes[(C::UInt::BYTE_SIZE - bits.len())..].copy_from_slice(bits);
        }
        cmp::Ordering::Greater => {
            // If bits is larger than the field size, truncate
            field_bytes.copy_from_slice(&bits[..C::UInt::BYTE_SIZE]);
        }
    }

    Ok(field_bytes)
}

#[cfg(test)]
mod tests {
    use super::bits2field;
    use elliptic_curve::dev::MockCurve;
    use hex_literal::hex;

    #[test]
    fn bits2field_too_small() {
        assert!(bits2field::<MockCurve>(b"").is_err());
    }

    #[test]
    fn bits2field_size_less() {
        let prehash = hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let field_bytes = bits2field::<MockCurve>(&prehash).unwrap();
        assert_eq!(
            field_bytes.as_slice(),
            &hex!("00000000000000000000000000000000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
    }

    #[test]
    fn bits2field_size_eq() {
        let prehash = hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let field_bytes = bits2field::<MockCurve>(&prehash).unwrap();
        assert_eq!(field_bytes.as_slice(), &prehash);
    }

    #[test]
    fn bits2field_size_greater() {
        let prehash = hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        let field_bytes = bits2field::<MockCurve>(&prehash).unwrap();
        assert_eq!(
            field_bytes.as_slice(),
            &hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
    }
}
