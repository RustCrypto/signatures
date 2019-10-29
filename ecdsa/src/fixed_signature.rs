//! Fixed-sized (a.k.a. "raw") ECDSA signatures

use crate::curve::Curve;
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
    ops::Add,
};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use signature::Error;

/// Size of a fixed sized signature for the given elliptic curve.
pub type Size<ScalarSize> = <ScalarSize as Add>::Output;

/// Fixed-sized (a.k.a. "raw") ECDSA signatures generic over elliptic curves.
///
/// These signatures are serialized as fixed-sized big endian scalar values
/// with no additional framing.
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
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
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

impl<'a, C: Curve> TryFrom<&'a [u8]> for FixedSignature<C>
where
    Size<C::ScalarSize>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
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
