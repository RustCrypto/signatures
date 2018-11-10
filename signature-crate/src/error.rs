//! Signature error types

use core::fmt;

/// Errors which can occur during signature operations
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Signature failed to verify
    SignatureInvalid,
}

impl Error {
    /// Get string description of this error
    pub fn as_str(self) -> &'static str {
        match self {
            Error::SignatureInvalid => "signature verification failed",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
