//! Signature error types

use core::fmt::{self, Display};

#[cfg(feature = "std")]
use std::boxed::Box;

/// Signature errors
#[derive(Debug, Default)]
pub struct Error {
    /// Cause of the error (if applicable)
    #[cfg(feature = "std")]
    cause: Option<Box<dyn std::error::Error>>,
}

impl Error {
    /// Create a new error with no cause
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new error with an associated cause.
    ///
    /// NOTE: The "cause" should NOT be used to propagate cryptographic errors
    /// e.g. signature parsing or verification errors.
    ///
    /// The intended use cases are for propagating errors related to external
    /// signers, e.g. communication/authentication errors with HSMs, KMS, etc.
    #[cfg(feature = "std")]
    pub fn from_cause<E>(cause: E) -> Self
    where
        E: Into<Box<dyn std::error::Error>>,
    {
        Self {
            cause: Some(cause.into()),
        }
    }

    /// Borrow the error's underlying cause (if available)
    #[cfg(feature = "std")]
    pub fn cause(&self) -> Option<&dyn std::error::Error> {
        self.cause.as_ref().map(|c| c.as_ref())
    }

    /// Extract the underlying cause of this error.
    ///
    /// Panics if the error does not have a cause.
    #[cfg(feature = "std")]
    pub fn into_cause(self) -> Box<dyn std::error::Error> {
        self.cause
            .expect("into_cause called on an error with no cause")
    }

    /// Attempt to downcast this error's cause into a concrete type
    #[cfg(feature = "std")]
    pub fn downcast<T>(self) -> Result<Box<T>, Box<dyn std::error::Error>>
    where
        T: std::error::Error + 'static,
    {
        self.cause
            .map(|cause| cause.downcast())
            .unwrap_or_else(|| Err(Error::new().into()))
    }

    /// Attempt to downcast a reference to this error's cause into a concrete type
    #[cfg(feature = "std")]
    pub fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: std::error::Error + 'static,
    {
        self.cause.as_ref().and_then(|cause| cause.downcast_ref())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signature error")?;

        #[cfg(feature = "std")]
        {
            if let Some(ref cause) = self.cause {
                write!(f, ": {}", cause)?;
            }
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.cause.as_ref().map(|cause| cause.as_ref())
    }
}
