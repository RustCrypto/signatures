//! Ed25519 signatures.
//!
//! Edwards Digital Signature Algorithm (EdDSA) over Curve25519 as specified in
//! RFC 8032: <https://tools.ietf.org/html/rfc8032>

#![no_std]

/// Re-export the `signature` crate
pub use signature::{self, Error};

use core::fmt::{self, Debug};

/// Length of an Ed25519 signature
pub const SIGNATURE_LENGTH: usize = 64;

/// Ed25519 signature.
#[derive(Copy, Clone)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// Create a new signature from a byte array
    pub fn new(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self::from(bytes)
    }

    /// Return the inner byte array
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.clone()
    }
}

impl signature::Signature for Signature {
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        let bytes = bytes.as_ref();

        if bytes.len() == SIGNATURE_LENGTH {
            let mut arr = [0u8; SIGNATURE_LENGTH];
            arr.copy_from_slice(bytes);
            Ok(Signature(arr))
        } else {
            Err(Error::new())
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for Signature {
    fn from(bytes: [u8; SIGNATURE_LENGTH]) -> Signature {
        Signature(bytes)
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({:?})", &self.0[..])
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl Eq for Signature {}
