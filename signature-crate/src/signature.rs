use core::fmt::Debug;

use error::Error;
#[allow(unused_imports)]
use prelude::*;

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
