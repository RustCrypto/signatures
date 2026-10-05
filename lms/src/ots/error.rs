//! LM-OTS Signing error

use core::error::Error;
use core::fmt::{Display, Formatter, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LmsOtsInvalidPrivateKey {}

impl Display for LmsOtsInvalidPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "private key is no longer valid")
    }
}

impl Error for LmsOtsInvalidPrivateKey {}
