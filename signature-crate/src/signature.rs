use core::fmt::Debug;

use crate::error::Error;
#[cfg(feature = "alloc")]
use crate::prelude::*;

/// Trait impl'd by concrete types that represent digital signatures
pub trait Signature: AsRef<[u8]> + Debug + Sized {
    /// Parse a signature from its byte representation
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error>;

    /// Borrow this signature as serialized bytes
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    /// Convert this signature into a byte vector
    #[cfg(feature = "alloc")]
    #[inline]
    fn into_vec(self) -> Vec<u8> {
        self.as_slice().into()
    }
}

/// Marker trait for "raw digest" signature algorithms, i.e. any algorithm
/// where signatures are exclusively computed as `S(H(m)))` where:
///
/// - `S`: signature algorithm
/// - `H`: hash (a.k.a. digest) function
/// - `m`: message
///
/// Notably this does not hold true for Ed25519, which hashes the input message
/// twice in an effort to remain secure even in the event of collisions in the
/// underlying hash function.
pub trait RawDigestSignature {}
