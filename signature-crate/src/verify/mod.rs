//! Trait for verifying digital signatures

#[cfg(feature = "digest")]
mod digest;

#[cfg(feature = "digest")]
pub use self::digest::VerifyDigest;
use crate::{error::Error, Signature};

/// Verify the provided message bytestring using `Self` (e.g. a public key)
pub trait Verify<S: Signature>: Send + Sync {
    /// Use `Self` to verify that the provided signature for a given message
    /// bytestring is authentic.
    ///
    /// Returns `Error` if it is inauthentic, or otherwise returns `()`.
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error>;
}
