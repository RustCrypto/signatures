//! Trait for producing digital signatures

use crate::{error::Error, Signature};

/// Sign the provided bytestring message using `Self` (e.g. a cryptographic key
/// or connection to an HSM), returning a digital signature.
pub trait Sign<S: Signature>: Send + Sync {
    /// Sign the given message and return a digital signature
    fn sign(&self, msg: &[u8]) -> Result<S, Error>;
}
