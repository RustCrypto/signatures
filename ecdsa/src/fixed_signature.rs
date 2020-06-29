//! Fixed-sized (a.k.a. "raw") ECDSA signatures

use crate::{
    curve::Curve,
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    Error,
};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
    ops::Add,
};

/// Size of a fixed sized signature for the given elliptic curve.
pub type Size<ScalarSize> = <ScalarSize as Add>::Output;

/// Fixed-sized (a.k.a. "raw") ECDSA signatures generic over elliptic curves.
///
/// These signatures are serialized as fixed-sized big endian scalar values
/// with no additional framing:
///
/// - `r`: field element size for the given curve, big-endian
/// - `s`: field element size for the given curve, big-endian
///
/// For example, in a curve with a 256-bit modulus like NIST P-256 or
/// secp256k1, `r` and `s` will both be 32-bytes, resulting in a signature
/// with a total of 64-bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct FixedSignature<C: Curve>
where
    Size<C::ScalarSize>: ArrayLength<u8>,
{
    bytes: GenericArray<u8, Size<C::ScalarSize>>,
}

impl<C: Curve> signature::Signature for FixedSignature<C>
where
    Size<C::ScalarSize>: ArrayLength<u8>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into()
    }
}

impl<C: Curve> AsRef<[u8]> for FixedSignature<C>
where
    Size<C::ScalarSize>: ArrayLength<u8>,
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<C: Curve> Debug for FixedSignature<C>
where
    Size<C::ScalarSize>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FixedSignature<{:?}> {{ bytes: {:?}) }}",
            C::default(),
            self.as_ref()
        )
    }
}

impl<C: Curve> TryFrom<&[u8]> for FixedSignature<C>
where
    Size<C::ScalarSize>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == <Size<C::ScalarSize>>::to_usize() {
            Ok(Self {
                bytes: GenericArray::clone_from_slice(bytes),
            })
        } else {
            Err(Error::new())
        }
    }
}

impl<C: Curve> From<GenericArray<u8, Size<C::ScalarSize>>> for FixedSignature<C>
where
    Size<C::ScalarSize>: ArrayLength<u8>,
{
    fn from(bytes: GenericArray<u8, Size<C::ScalarSize>>) -> Self {
        Self { bytes }
    }
}
