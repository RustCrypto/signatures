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

/// Marker trait for `Signature` types computable as `S(H(m))`
///
/// - `S`: signature algorithm
/// - `H`: hash (a.k.a. digest) function
/// - `m`: message
///
/// For signature types that implement this trait, a blanket impl of
/// `Signer` will be provided for all types that `impl DigestSigner`
/// along with a corresponding impl of `Verifier` for all types that
/// `impl DigestVerifier`.
#[cfg(feature = "digest")]
pub trait DigestSignature: Signature {
    /// Preferred `Digest` algorithm to use when computing this signature type.
    type Digest: digest::Digest;
}
