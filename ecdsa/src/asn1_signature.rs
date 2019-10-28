//! ASN.1 DER-encoded ECDSA signatures

use crate::curve::Curve;
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
type MaxOverhead = generic_array::typenum::U9;

/// Maximum size of an ASN.1 DER encoded signature for the given elliptic curve.
// TODO(tarcieri): const generics
pub type MaxSize<ScalarSize> = <<ScalarSize as Add>::Output as Add<MaxOverhead>>::Output;

/// ASN.1 DER-encoded ECDSA signature generic over elliptic curves.
pub struct Asn1Signature<C: Curve>
where
    <C::ScalarSize as Add>::Output: Add<MaxOverhead>,
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// ASN.1 DER-encoded signature data
    bytes: GenericArray<u8, MaxSize<C::ScalarSize>>,

    /// Length of the signature in bytes (DER is variable-width)
    length: usize,
}

impl<C: Curve> signature::Signature for Asn1Signature<C>
where
    <C::ScalarSize as Add>::Output: Add<MaxOverhead>,
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
{
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
    }
}

impl<C: Curve> AsRef<[u8]> for Asn1Signature<C>
where
    <C::ScalarSize as Add>::Output: Add<MaxOverhead>,
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
{
    fn as_ref(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.length]
    }
}

impl<C: Curve> Debug for Asn1Signature<C>
where
    <C::ScalarSize as Add>::Output: Add<MaxOverhead>,
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
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
    <C::ScalarSize as Add>::Output: Add<MaxOverhead>,
    MaxSize<C::ScalarSize>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self, Error> {
        let length = slice.len();

        // TODO: better validate signature is well-formed ASN.1 DER
        if <MaxSize<C::ScalarSize>>::to_usize() < length {
            return Err(Error::new());
        }

        let mut bytes = GenericArray::default();
        bytes.as_mut_slice()[..length].copy_from_slice(slice);
        Ok(Self { bytes, length })
    }
}
