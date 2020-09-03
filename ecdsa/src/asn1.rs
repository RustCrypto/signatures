//! Support for ECDSA signatures encoded as ASN.1 DER.

// Adapted from BearSSL. Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>.
// Relicensed under Apache 2.0 + MIT (from original MIT) with permission.
//
// <https://www.bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/ec/ecdsa_atr.c>
// <https://www.bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/ec/ecdsa_rta.c>

use crate::{
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    Error,
};
use core::{
    convert::{TryFrom, TryInto},
    fmt,
    ops::{Add, Range},
};
use elliptic_curve::{consts::U9, weierstrass::Curve};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Maximum overhead of an ASN.1 DER-encoded ECDSA signature for a given curve:
/// 9-bytes.
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
pub type MaxOverhead = U9;

/// Maximum size of an ASN.1 DER encoded signature for the given elliptic curve.
pub type MaxSize<C> =
    <<<C as elliptic_curve::Curve>::FieldSize as Add>::Output as Add<MaxOverhead>>::Output;

/// Byte array containing a serialized ASN.1 signature
type DocumentBytes<C> = GenericArray<u8, MaxSize<C>>;

/// ASN.1 `INTEGER` tag
const INTEGER_TAG: u8 = 0x02;

/// ASN.1 `SEQUENCE` tag
const SEQUENCE_TAG: u8 = 0x30;

/// ASN.1 DER-encoded signature.
///
/// Generic over the scalar size of the elliptic curve.
pub struct Signature<C>
where
    C: Curve,
    C::FieldSize: Add + ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    <C::FieldSize as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    /// ASN.1 DER-encoded signature data
    bytes: DocumentBytes<C>,

    /// Range of the `r` value within the signature
    r_range: Range<usize>,

    /// Range of the `s` value within the signature
    s_range: Range<usize>,
}

impl<C> signature::Signature for Signature<C>
where
    C: Curve,
    C::FieldSize: Add + ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    <C::FieldSize as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    /// Parse an ASN.1 DER-encoded ECDSA signature from a byte slice
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into()
    }
}

#[allow(clippy::len_without_is_empty)]
impl<C> Signature<C>
where
    C: Curve,
    C::FieldSize: Add + ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    <C::FieldSize as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    /// Get the length of the signature in bytes
    pub fn len(&self) -> usize {
        self.s_range.end
    }

    /// Borrow this signature as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.len()]
    }

    /// Serialize this signature as a boxed byte slice
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.as_bytes().to_vec().into_boxed_slice()
    }

    /// Create an ASN.1 DER encoded signature from big endian `r` and `s` scalars
    pub(crate) fn from_scalar_bytes(r: &[u8], s: &[u8]) -> Self {
        let r_len = int_length(r);
        let s_len = int_length(s);
        let scalar_size = C::FieldSize::to_usize();
        let mut bytes = DocumentBytes::<C>::default();

        // SEQUENCE header
        bytes[0] = SEQUENCE_TAG as u8;
        let zlen = r_len.checked_add(s_len).unwrap().checked_add(4).unwrap();

        let offset = if zlen >= 0x80 {
            bytes[1] = 0x81;
            bytes[2] = zlen as u8;
            3
        } else {
            bytes[1] = zlen as u8;
            2
        };

        // First INTEGER (r)
        serialize_int(r, &mut bytes[offset..], r_len, scalar_size);
        let r_end = offset.checked_add(2).unwrap().checked_add(r_len).unwrap();

        // Second INTEGER (s)
        serialize_int(s, &mut bytes[r_end..], s_len, scalar_size);
        let s_end = r_end.checked_add(2).unwrap().checked_add(s_len).unwrap();

        bytes[..s_end]
            .try_into()
            .expect("generated invalid ASN.1 DER")
    }

    /// Get the `r` component of the signature (leading zeros removed)
    pub(crate) fn r(&self) -> &[u8] {
        &self.bytes[self.r_range.clone()]
    }

    /// Get the `s` component of the signature (leading zeros removed)
    pub(crate) fn s(&self) -> &[u8] {
        &self.bytes[self.s_range.clone()]
    }
}

impl<C> AsRef<[u8]> for Signature<C>
where
    C: Curve,
    C::FieldSize: Add + ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    <C::FieldSize as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C> fmt::Debug for Signature<C>
where
    C: Curve,
    C::FieldSize: Add + ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    <C::FieldSize as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("asn1::Signature")
            .field("r", &self.r())
            .field("s", &self.s())
            .finish()
    }
}

impl<C> TryFrom<&[u8]> for Signature<C>
where
    C: Curve,
    C::FieldSize: Add + ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    <C::FieldSize as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        // Signature format is a SEQUENCE of two INTEGER values. We
        // support only integers of less than 127 bytes each (signed
        // encoding) so the resulting raw signature will have length
        // at most 254 bytes.
        //
        // First byte is SEQUENCE tag.
        if bytes[0] != SEQUENCE_TAG as u8 {
            return Err(Error::new());
        }

        // The SEQUENCE length will be encoded over one or two bytes. We
        // limit the total SEQUENCE contents to 255 bytes, because it
        // makes things simpler; this is enough for subgroup orders up
        // to 999 bits.
        let mut zlen = bytes[1] as usize;

        let offset = if zlen > 0x80 {
            if zlen != 0x81 {
                return Err(Error::new());
            }

            zlen = bytes[2] as usize;
            3
        } else {
            2
        };

        if zlen != bytes.len().checked_sub(offset).unwrap() {
            return Err(Error::new());
        }

        // First INTEGER (r)
        let r_range = parse_int(&bytes[offset..], C::FieldSize::to_usize())?;
        let r_start = offset.checked_add(r_range.start).unwrap();
        let r_end = offset.checked_add(r_range.end).unwrap();

        // Second INTEGER (s)
        let s_range = parse_int(&bytes[r_end..], C::FieldSize::to_usize())?;
        let s_start = r_end.checked_add(s_range.start).unwrap();
        let s_end = r_end.checked_add(s_range.end).unwrap();

        if s_end != bytes.as_ref().len() {
            return Err(Error::new());
        }

        let mut byte_arr = DocumentBytes::<C>::default();
        byte_arr[..s_end].copy_from_slice(bytes.as_ref());

        Ok(Signature {
            bytes: byte_arr,
            r_range: Range {
                start: r_start,
                end: r_end,
            },
            s_range: Range {
                start: s_start,
                end: s_end,
            },
        })
    }
}

#[cfg(all(feature = "digest", feature = "hazmat"))]
impl<C> signature::PrehashSignature for Signature<C>
where
    C: Curve + crate::hazmat::DigestPrimitive,
    C::FieldSize: Add + ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    <C::FieldSize as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    type Digest = C::Digest;
}

/// Parse an integer from its ASN.1 DER serialization
fn parse_int(bytes: &[u8], scalar_size: usize) -> Result<Range<usize>, Error> {
    if bytes.len() < 3 {
        return Err(Error::new());
    }

    if bytes[0] != INTEGER_TAG as u8 {
        return Err(Error::new());
    }

    let len = bytes[1] as usize;

    if len >= 0x80 || len.checked_add(2).unwrap() > bytes.len() {
        return Err(Error::new());
    }

    let mut start = 2usize;
    let end = start.checked_add(len).unwrap();

    start = start
        .checked_add(trim_zeroes(&bytes[start..end], scalar_size)?)
        .unwrap();

    Ok(Range { start, end })
}

/// Serialize scalar as ASN.1 DER
fn serialize_int(scalar: &[u8], out: &mut [u8], len: usize, scalar_size: usize) {
    out[0] = INTEGER_TAG as u8;
    out[1] = len as u8;

    if len > scalar_size {
        out[2] = 0x00;
        out[3..scalar_size.checked_add(3).unwrap()].copy_from_slice(scalar);
    } else {
        out[2..len.checked_add(2).unwrap()]
            .copy_from_slice(&scalar[scalar_size.checked_sub(len).unwrap()..]);
    }
}

/// Compute ASN.1 DER encoded length for the provided scalar. The ASN.1
/// encoding is signed, so its leading bit must have value 0; it must also be
/// of minimal length (so leading bytes of value 0 must be removed, except if
/// that would contradict the rule about the sign bit).
fn int_length(mut x: &[u8]) -> usize {
    while !x.is_empty() && x[0] == 0 {
        x = &x[1..];
    }

    if x.is_empty() || x[0] >= 0x80 {
        x.len().checked_add(1).unwrap()
    } else {
        x.len()
    }
}

/// Compute an offset within an ASN.1 INTEGER after skipping leading zeroes
fn trim_zeroes(mut bytes: &[u8], scalar_size: usize) -> Result<usize, Error> {
    let mut offset = 0;

    if bytes.len() > scalar_size {
        if bytes.len() != scalar_size.checked_add(1).unwrap() {
            return Err(Error::new());
        }

        if bytes[0] != 0 {
            return Err(Error::new());
        }

        bytes = &bytes[1..];
        offset += 1;
    }

    while !bytes.is_empty() && bytes[0] == 0 {
        bytes = &bytes[1..];
        offset += 1;
    }

    Ok(offset)
}

#[cfg(all(feature = "dev", test))]
mod tests {
    use crate::dev::curve::Signature;
    use signature::Signature as _;

    const EXAMPLE_SIGNATURE: [u8; 64] = [
        0xf3, 0xac, 0x80, 0x61, 0xb5, 0x14, 0x79, 0x5b, 0x88, 0x43, 0xe3, 0xd6, 0x62, 0x95, 0x27,
        0xed, 0x2a, 0xfd, 0x6b, 0x1f, 0x6a, 0x55, 0x5a, 0x7a, 0xca, 0xbb, 0x5e, 0x6f, 0x79, 0xc8,
        0xc2, 0xac, 0x8b, 0xf7, 0x78, 0x19, 0xca, 0x5, 0xa6, 0xb2, 0x78, 0x6c, 0x76, 0x26, 0x2b,
        0xf7, 0x37, 0x1c, 0xef, 0x97, 0xb2, 0x18, 0xe9, 0x6f, 0x17, 0x5a, 0x3c, 0xcd, 0xda, 0x2a,
        0xcc, 0x5, 0x89, 0x3,
    ];

    #[test]
    fn test_fixed_to_asn1_signature_roundtrip() {
        let signature1 = Signature::from_bytes(&EXAMPLE_SIGNATURE).unwrap();

        // Convert to ASN.1 DER and back
        let asn1_signature = signature1.to_asn1();
        let signature2 = Signature::from_asn1(asn1_signature.as_ref()).unwrap();

        assert_eq!(signature1, signature2);
    }
}
