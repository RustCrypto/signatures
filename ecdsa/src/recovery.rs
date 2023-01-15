//! Public key recovery support.

use crate::{Error, Result};

#[cfg(feature = "verifying")]
use {
    crate::{
        hazmat::{bits2field, DigestPrimitive, VerifyPrimitive},
        Signature, SignatureSize, VerifyingKey,
    },
    elliptic_curve::{
        generic_array::ArrayLength,
        ops::{Invert, LinearCombination, Reduce},
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        AffinePoint, DecompressPoint, FieldSize, Group, PrimeCurve, PrimeField,
        ProjectiveArithmetic, ProjectivePoint, Scalar,
    },
    signature::{digest::Digest, hazmat::PrehashVerifier},
};

/// Recovery IDs, a.k.a. "recid".
///
/// This is an integer value `0`, `1`, `2`, or `3` included along with a
/// signature which is used during the recovery process to select the correct
/// public key from the signature.
///
/// It consists of two bits of information:
///
/// - low bit (0/1): was the y-coordinate of the affine point resulting from
///   the fixed-base multiplication 𝑘×𝑮 odd? This part of the algorithm
///   functions similar to point decompression.
/// - hi bit (3/4): did the affine x-coordinate of 𝑘×𝑮 overflow the order of
///   the scalar field, requiring a reduction when computing `r`?
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct RecoveryId(u8);

impl RecoveryId {
    /// Maximum supported value for the recovery ID (inclusive).
    pub const MAX: u8 = 3;

    /// Create a new [`RecoveryId`] from the following 1-bit arguments:
    ///
    /// - `is_y_odd`: is the affine y-coordinate of 𝑘×𝑮 odd?
    /// - `is_x_reduced`: did the affine x-coordinate of 𝑘×𝑮 overflow the curve order?
    pub const fn new(is_y_odd: bool, is_x_reduced: bool) -> Self {
        Self((is_x_reduced as u8) << 1 | (is_y_odd as u8))
    }

    /// Did the affine x-coordinate of 𝑘×𝑮 overflow the curve order?
    pub const fn is_x_reduced(self) -> bool {
        (self.0 & 0b10) != 0
    }

    /// Is the affine y-coordinate of 𝑘×𝑮 odd?
    pub const fn is_y_odd(self) -> bool {
        (self.0 & 1) != 0
    }

    /// Convert a `u8` into a [`RecoveryId`].
    pub const fn from_byte(byte: u8) -> Option<Self> {
        if byte <= Self::MAX {
            Some(Self(byte))
        } else {
            None
        }
    }

    /// Convert this [`RecoveryId`] into a `u8`.
    pub const fn to_byte(self) -> u8 {
        self.0
    }
}

#[cfg(feature = "verifying")]
impl RecoveryId {
    /// Given a public key, message, and signature, use trial recovery
    /// to determine if a suitable recovery ID exists, or return an error
    /// otherwise.
    pub fn trial_recovery_from_msg<C>(
        verifying_key: &VerifyingKey<C>,
        msg: &[u8],
        signature: &Signature<C>,
    ) -> Result<Self>
    where
        C: DigestPrimitive + PrimeCurve + ProjectiveArithmetic,
        AffinePoint<C>:
            DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
        FieldSize<C>: sec1::ModulusSize,
        Scalar<C>: Reduce<C::UInt>,
        SignatureSize<C>: ArrayLength<u8>,
    {
        Self::trial_recovery_from_digest(verifying_key, C::Digest::new_with_prefix(msg), signature)
    }

    /// Given a public key, message digest, and signature, use trial recovery
    /// to determine if a suitable recovery ID exists, or return an error
    /// otherwise.
    pub fn trial_recovery_from_digest<C, D>(
        verifying_key: &VerifyingKey<C>,
        digest: D,
        signature: &Signature<C>,
    ) -> Result<Self>
    where
        C: PrimeCurve + ProjectiveArithmetic,
        D: Digest,
        AffinePoint<C>:
            DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
        FieldSize<C>: sec1::ModulusSize,
        Scalar<C>: Reduce<C::UInt>,
        SignatureSize<C>: ArrayLength<u8>,
    {
        Self::trial_recovery_from_prehash(verifying_key, &digest.finalize(), signature)
    }

    /// Given a public key, message digest, and signature, use trial recovery
    /// to determine if a suitable recovery ID exists, or return an error
    /// otherwise.
    pub fn trial_recovery_from_prehash<C>(
        verifying_key: &VerifyingKey<C>,
        prehash: &[u8],
        signature: &Signature<C>,
    ) -> Result<Self>
    where
        C: PrimeCurve + ProjectiveArithmetic,
        AffinePoint<C>:
            DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
        FieldSize<C>: sec1::ModulusSize,
        Scalar<C>: Reduce<C::UInt>,
        SignatureSize<C>: ArrayLength<u8>,
    {
        for id in 0..=Self::MAX {
            let recovery_id = RecoveryId(id);

            if let Ok(vk) = VerifyingKey::recover_from_prehash(prehash, signature, recovery_id) {
                if verifying_key == &vk {
                    return Ok(recovery_id);
                }
            }
        }

        Err(Error::new())
    }
}

impl TryFrom<u8> for RecoveryId {
    type Error = Error;

    fn try_from(byte: u8) -> Result<Self> {
        Self::from_byte(byte).ok_or_else(Error::new)
    }
}

impl From<RecoveryId> for u8 {
    fn from(id: RecoveryId) -> u8 {
        id.0
    }
}

#[cfg(feature = "verifying")]
impl<C> VerifyingKey<C>
where
    C: PrimeCurve + ProjectiveArithmetic,
    AffinePoint<C>:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldSize<C>: sec1::ModulusSize,
    Scalar<C>: Reduce<C::UInt>,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Recover a [`VerifyingKey`] from the given message, signature, and
    /// [`RecoveryId`].
    ///
    /// The message is first hashed using this curve's [`DigestPrimitive`].
    pub fn recover_from_msg(
        msg: &[u8],
        signature: &Signature<C>,
        recovery_id: RecoveryId,
    ) -> Result<Self>
    where
        C: DigestPrimitive,
    {
        Self::recover_from_digest(C::Digest::new_with_prefix(msg), signature, recovery_id)
    }

    /// Recover a [`VerifyingKey`] from the given message [`Digest`],
    /// signature, and [`RecoveryId`].
    pub fn recover_from_digest<D>(
        msg_digest: D,
        signature: &Signature<C>,
        recovery_id: RecoveryId,
    ) -> Result<Self>
    where
        D: Digest,
    {
        Self::recover_from_prehash(&msg_digest.finalize(), signature, recovery_id)
    }

    /// Recover a [`VerifyingKey`] from the given `prehash` of a message, the
    /// signature over that prehashed message, and a [`RecoveryId`].
    // TODO(tarcieri): handle `is_x_reduced` case (RustCrypto/signatures#583)
    #[allow(non_snake_case)]
    pub fn recover_from_prehash(
        prehash: &[u8],
        signature: &Signature<C>,
        recovery_id: RecoveryId,
    ) -> Result<Self> {
        let (r, s) = signature.split_scalars();
        let z = <Scalar<C> as Reduce<C::UInt>>::from_be_bytes_reduced(bits2field::<C>(prehash)?);
        let R = AffinePoint::<C>::decompress(&r.to_repr(), u8::from(recovery_id.is_y_odd()).into());

        if R.is_none().into() {
            return Err(Error::new());
        }

        let R = ProjectivePoint::<C>::from(R.unwrap());
        let r_inv = *r.invert();
        let u1 = -(r_inv * z);
        let u2 = r_inv * *s;
        let pk = ProjectivePoint::<C>::lincomb(&ProjectivePoint::<C>::generator(), &u1, &R, &u2);
        let vk = Self::from_affine(pk.into())?;

        // Ensure signature verifies with the recovered key
        vk.verify_prehash(prehash, signature)?;

        Ok(vk)
    }
}

#[cfg(test)]
mod tests {
    use super::RecoveryId;

    #[test]
    fn new() {
        assert_eq!(RecoveryId::new(false, false).to_byte(), 0);
        assert_eq!(RecoveryId::new(true, false).to_byte(), 1);
        assert_eq!(RecoveryId::new(false, true).to_byte(), 2);
        assert_eq!(RecoveryId::new(true, true).to_byte(), 3);
    }

    #[test]
    fn try_from() {
        for n in 0u8..=3 {
            assert_eq!(RecoveryId::try_from(n).unwrap().to_byte(), n);
        }

        for n in 4u8..=255 {
            assert!(RecoveryId::try_from(n).is_err());
        }
    }

    #[test]
    fn is_x_reduced() {
        assert_eq!(RecoveryId::try_from(0).unwrap().is_x_reduced(), false);
        assert_eq!(RecoveryId::try_from(1).unwrap().is_x_reduced(), false);
        assert_eq!(RecoveryId::try_from(2).unwrap().is_x_reduced(), true);
        assert_eq!(RecoveryId::try_from(3).unwrap().is_x_reduced(), true);
    }

    #[test]
    fn is_y_odd() {
        assert_eq!(RecoveryId::try_from(0).unwrap().is_y_odd(), false);
        assert_eq!(RecoveryId::try_from(1).unwrap().is_y_odd(), true);
        assert_eq!(RecoveryId::try_from(2).unwrap().is_y_odd(), false);
        assert_eq!(RecoveryId::try_from(3).unwrap().is_y_odd(), true);
    }
}
