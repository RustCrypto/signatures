//! LMS Signing error

use core::error::Error;
use core::fmt::{Display, Formatter, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LmsOutOfPrivateKeys {}

impl Display for LmsOutOfPrivateKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "private key has been exhausted")
    }
}

impl Error for LmsOutOfPrivateKeys {}
