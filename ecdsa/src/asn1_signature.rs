//! ASN.1 DER-encoded ECDSA signatures

use crate::{curve::Curve, scalar_pair::ScalarPair};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
    ops::Add,
};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use signature::Error;

/// Maximum overhead of an ASN.1 DER-encoded ECDSA signature for a given curve:
/// 9 bytes.
///
/// Includes 3-byte ASN.1 DER header:
///
/// - 1-byte: ASN.1 `SEQUENCE` tag (0x30)
/// - 2-byte: length
///
/// ...followed by two ASN.1 `INTEGER` values, which each have a header whose
/// maximum length is the following:
///
/// - 1-byte: ASN.1 `INTEGER` tag (0x02)
/// - 1-byte: length
/// - 1-byte: zero to indicate value is positive (`INTEGER` is signed)
pub type MaxOverhead = generic_array::typenum::U9;

/// Maximum size of an ASN.1 DER encoded signature for the given elliptic curve.
// TODO(tarcieri): const generics
pub type MaxSize<ScalarSize> = <<ScalarSize as Add>::Output as Add<MaxOverhead>>::Output;

/// ASN.1 DER-encoded ECDSA signature generic over elliptic curves.
pub struct Asn1Signature<C: Curve>
where
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
    <C::ScalarSize as Add>::Output: ArrayLength<u8> + Add<MaxOverhead>,
{
    /// ASN.1 DER-encoded signature data
    pub(crate) bytes: GenericArray<u8, MaxSize<C::ScalarSize>>,

    /// Length of the signature in bytes (DER is variable-width)
    pub(crate) length: usize,
}

impl<C: Curve> signature::Signature for Asn1Signature<C>
where
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
    <C::ScalarSize as Add>::Output: ArrayLength<u8> + Add<MaxOverhead>,
{
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
    }
}

impl<C: Curve> AsRef<[u8]> for Asn1Signature<C>
where
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
    <C::ScalarSize as Add>::Output: ArrayLength<u8> + Add<MaxOverhead>,
{
    fn as_ref(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.length]
    }
}

impl<C: Curve> Debug for Asn1Signature<C>
where
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
    <C::ScalarSize as Add>::Output: ArrayLength<u8> + Add<MaxOverhead>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Asn1Signature<{:?}> {{ bytes: {:?}) }}",
            C::default(),
            self.as_ref()
        )
    }
}

impl<'a, C: Curve> TryFrom<&'a [u8]> for Asn1Signature<C>
where
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
    <C::ScalarSize as Add>::Output: ArrayLength<u8> + Add<MaxOverhead>,
{
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self, Error> {
        let length = slice.len();

        if <MaxSize<C::ScalarSize>>::to_usize() < length {
            return Err(Error::new());
        }

        let mut bytes = GenericArray::default();
        bytes.as_mut_slice()[..length].copy_from_slice(slice);
        let result = Self { bytes, length };

        // Ensure signature is well-formed ASN.1 DER
        ScalarPair::from_asn1_signature(&result).ok_or_else(Error::new)?;

        Ok(result)
    }
}
