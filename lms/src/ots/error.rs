//! LM-OTS Signing error

use std::error::Error;
use std::fmt::{Display, Formatter, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LmsOtsSigningError {
    InvalidPrivateKey,
}

impl Display for LmsOtsSigningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::InvalidPrivateKey => {
                write!(f, "private key is no longer valid")
            }
        }
    }
}

impl Error for LmsOtsSigningError {}
