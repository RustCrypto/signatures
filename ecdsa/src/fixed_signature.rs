//! Fixed-sized (a.k.a. "raw") ECDSA signatures

use crate::curve::Curve;
use core::{fmt, ops::Add};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use signature::Error;

/// Size of a fixed sized signature: double that of the scalar size
// TODO(tarcieri): use typenum's `Double` op or switch to const generics
pub type FixedSignatureSize<C> =
    <<C as Curve>::ScalarSize as Add<<C as Curve>::ScalarSize>>::Output;

/// Fixed-sized (a.k.a. "raw") ECDSA signatures: serialized as fixed-sized
/// big endian scalar values with no additional framing.
#[derive(Clone, Eq, PartialEq)]
pub struct FixedSignature<C>
where
    C: Curve,
    FixedSignatureSize<C>: ArrayLength<u8>,
{
    bytes: GenericArray<u8, FixedSignatureSize<C>>,
}

impl<C> signature::Signature for FixedSignature<C>
where
    C: Curve,
    FixedSignatureSize<C>: ArrayLength<u8>,
{
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        if bytes.as_ref().len() == <FixedSignatureSize<C>>::to_usize() {
            Ok(Self {
                bytes: GenericArray::clone_from_slice(bytes.as_ref()),
            })
        } else {
            Err(Error::new())
        }
    }
}

impl<C> AsRef<[u8]> for FixedSignature<C>
where
    C: Curve,
    FixedSignatureSize<C>: ArrayLength<u8>,
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<C> fmt::Debug for FixedSignature<C>
where
    C: Curve,
    FixedSignatureSize<C>: ArrayLength<u8>,
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
