//! Public key recovery support.

use crate::{Error, Result};

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

#[cfg(all(feature = "arithmetic", feature = "verify"))]
mod signature {
    use core::ops::Add;

    use crate::{
        hazmat::{DigestPrimitive, VerifyPrimitive},
        RecoveryId, SignatureSize, VerifyingKey,
    };
    use elliptic_curve::{
        generic_array::{
            typenum::{Add1, Unsigned, B1},
            ArrayLength, GenericArray,
        },
        ops::Reduce,
        ops::{Invert, LinearCombination},
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        AffinePoint, DecompressPoint, FieldBytes, FieldSize, Group, PrimeCurve, PrimeField,
        ProjectiveArithmetic, ProjectivePoint, Scalar,
    };
    use signature::{digest::Digest, hazmat::PrehashVerifier, Error, Result, SignatureEncoding};

    /// ECDSA signature with Ethereum-style "recoverable signatures" support
    #[derive(Clone, Eq, PartialEq)]
    pub struct Signature<C>
    where
        C: PrimeCurve,
    {
        inner: crate::Signature<C>,
        recovery_id: RecoveryId,
    }

    impl<C> Signature<C>
    where
        C: PrimeCurve,
    {
        /// Create a new signature with recovery support
        pub fn new(inner: crate::Signature<C>, recovery_id: RecoveryId) -> Self {
            Self { inner, recovery_id }
        }
    }

    impl<C> Signature<C>
    where
        C: DigestPrimitive + ProjectiveArithmetic + PrimeCurve,
        SignatureSize<C>: ArrayLength<u8>,
        Scalar<C>: Reduce<C::UInt>,
        AffinePoint<C>: DecompressPoint<C>
            + From<ProjectivePoint<C>>
            + FromEncodedPoint<C>
            + ToEncodedPoint<C>
            + VerifyPrimitive<C>,
        FieldSize<C>: sec1::ModulusSize,
    {
        /// Attempt to create a recoverable signature from a verifying key, message and its signature
        ///
        /// Uses the curve associated digest for hashing the message
        pub fn from_trail_recovery(
            verifying_key: &VerifyingKey<C>,
            message: &[u8],
            signature: crate::Signature<C>,
        ) -> Result<Self>
        where
            <C as DigestPrimitive>::Digest: Digest<OutputSize = FieldSize<C>>,
        {
            Self::from_digest_trial_recovery(
                verifying_key,
                <<C as DigestPrimitive>::Digest>::new_with_prefix(message),
                signature,
            )
        }

        /// Attempt to create a recoverable signature from a verifying key, processed message and its signature
        #[allow(clippy::unwrap_used)]
        pub fn from_digest_trial_recovery<D>(
            verifying_key: &VerifyingKey<C>,
            digest: D,
            signature: crate::Signature<C>,
        ) -> Result<Self>
        where
            D: Digest<OutputSize = FieldSize<C>>,
        {
            let hash = digest.finalize();

            for i in 0..=1 {
                let recoverable_signature =
                    Self::new(signature.clone(), RecoveryId::from_byte(i).unwrap());

                if let Ok(recovered_key) =
                    recoverable_signature.recover_verifying_key_from_digest_bytes(hash.clone())
                {
                    if recovered_key == *verifying_key
                        && recovered_key.verify_prehash(&hash, &signature).is_ok()
                    {
                        return Ok(recoverable_signature);
                    }
                }
            }

            Err(Error::new())
        }

        /// Recover the verifying key via the digest
        pub fn recover_verifying_key_from_digest<D>(&self, digest: D) -> Result<VerifyingKey<C>>
        where
            D: Digest<OutputSize = FieldSize<C>>,
        {
            self.recover_verifying_key_from_digest_bytes(digest.finalize())
        }

        /// Recover the verifying key via the digest bytes
        #[allow(non_snake_case)]
        pub fn recover_verifying_key_from_digest_bytes(
            &self,
            digest_bytes: FieldBytes<C>,
        ) -> Result<VerifyingKey<C>> {
            let r = self.inner.r();
            let s = self.inner.s();
            let z = <Scalar<C> as Reduce<C::UInt>>::from_be_bytes_reduced(digest_bytes);
            let R = AffinePoint::<C>::decompress(
                &r.to_repr(),
                u8::from(self.recovery_id.is_y_odd()).into(),
            );

            if R.is_none().into() {
                return Err(Error::new());
            }

            let R = ProjectivePoint::<C>::from(R.unwrap());
            let r_inv = *r.invert();
            let u1 = -(r_inv * z);
            let u2 = r_inv * *s;
            let pk =
                ProjectivePoint::<C>::lincomb(&ProjectivePoint::<C>::generator(), &u1, &R, &u2)
                    .into();

            VerifyingKey::from_affine(pk)
        }
    }

    impl<C> SignatureEncoding for Signature<C>
    where
        C: PrimeCurve,
        SignatureSize<C>: Add<B1> + ArrayLength<u8>,
        <SignatureSize<C> as Add<B1>>::Output: ArrayLength<u8>,
    {
        type Repr = GenericArray<u8, Add1<SignatureSize<C>>>;
    }

    impl<C> From<Signature<C>> for GenericArray<u8, Add1<SignatureSize<C>>>
    where
        C: PrimeCurve,
        SignatureSize<C>: Add<B1> + ArrayLength<u8>,
        <SignatureSize<C> as Add<B1>>::Output: ArrayLength<u8>,
    {
        fn from(sig: Signature<C>) -> Self {
            let mut serialised_array = <Signature<C> as SignatureEncoding>::Repr::default();
            let mut_serialised_array = serialised_array.as_mut_slice();
            let inner_sig = sig.inner.to_bytes();

            mut_serialised_array[..inner_sig.len()].copy_from_slice(&inner_sig);
            mut_serialised_array[inner_sig.len()] = sig.recovery_id.to_byte();
            serialised_array
        }
    }

    impl<C> TryFrom<&[u8]> for Signature<C>
    where
        C: PrimeCurve,
        SignatureSize<C>: Add<B1> + ArrayLength<u8>,
        <SignatureSize<C> as Add<B1>>::Output: ArrayLength<u8>,
    {
        type Error = Error;

        fn try_from(value: &[u8]) -> Result<Self> {
            let signature = crate::Signature::try_from(&value[..SignatureSize::<C>::to_usize()])?;
            let recovery_id = RecoveryId::from_byte(value[SignatureSize::<C>::to_usize()])
                .ok_or_else(Error::new)?;
            Ok(Self::new(signature, recovery_id))
        }
    }
}

#[cfg(all(feature = "arithmetic", feature = "verify"))]
pub use self::signature::Signature as RecoverySignature;

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
