//! LMS Signing error

use std::error::Error;
use std::fmt::{Display, Formatter, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LmsSigningError {
    OutOfPrivateKeys,
}

impl Display for LmsSigningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::OutOfPrivateKeys => {
                write!(f, "private key has been exhausted")
            }
        }
    }
}

impl Error for LmsSigningError {}
