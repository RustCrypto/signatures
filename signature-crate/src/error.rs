//! Signature error types

use core::fmt::{self, Display};

#[cfg(feature = "std")]
use std::{boxed::Box, error::Error as StdError};

/// Signature errors
#[derive(Debug, Default)]
pub struct Error {
    /// Cause of the error (if applicable)
    #[cfg(feature = "std")]
    cause: Option<Box<dyn StdError>>,
}

impl Error {
    /// Create a new error with no cause
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new error from a cause
    #[cfg(feature = "std")]
    pub fn from_cause<E>(cause: E) -> Self
    where
        E: Into<Box<dyn StdError>>,
    {
        Self {
            cause: Some(cause.into()),
        }
    }

    /// Extract the underlying cause of this error.
    ///
    /// Panics if the error does not have a cause.
    #[cfg(feature = "std")]
    pub fn into_cause(self) -> Box<dyn StdError> {
        self.cause
            .expect("into_cause called on an error with no cause")
    }

    /// Attempt to downcast this error's cause into a concrete type
    #[cfg(feature = "std")]
    pub fn downcast<T>(self) -> Result<Box<T>, Box<dyn StdError>>
    where
        T: StdError + 'static,
    {
        self.cause
            .map(|cause| cause.downcast())
            .unwrap_or_else(|| Err(Error::new().into()))
    }

    /// Attempt to downcast a reference to this error's cause into a concrete type
    #[cfg(feature = "std")]
    pub fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: StdError + 'static,
    {
        self.cause.as_ref().and_then(|cause| cause.downcast_ref())
    }
}

#[cfg(not(feature = "std"))]
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signature error")
    }
}

#[cfg(feature = "std")]
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref cause) = self.cause {
            write!(f, "{}", cause)
        } else {
            write!(f, "signature error")
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        self.cause.as_ref().map(|cause| cause.as_ref())
    }
}
