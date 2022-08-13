#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "sign")]
mod sign;

#[cfg(feature = "verify")]
mod verify;

use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use signature::{Result, Signature as SignSignature};

#[cfg(feature = "sign")]
pub use crate::sign::*;

#[cfg(feature = "verify")]
pub use crate::verify::*;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(not(feature = "alloc"))]
/// Limit ourselves to RSA16384 as an unsane boundary
const MAX_RSA_SIZE: usize = 16384 / 8;

#[cfg(not(feature = "alloc"))]
/// Generic RSA Signature implementation
#[derive(Clone, Copy)]
pub struct Signature {
    len: usize,
    bytes: [u8; MAX_RSA_SIZE],
}

#[cfg(not(feature = "alloc"))]
impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut s = Signature {
            len: bytes.len(),
            bytes: [0; MAX_RSA_SIZE],
        };
        s.bytes[0..bytes.len()].copy_from_slice(bytes);
        Ok(s)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[cfg(feature = "alloc")]
/// Generic RSA Signature implementation
#[derive(Clone)]
pub struct Signature {
    bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut s = Signature {
            bytes: bytes.into(),
        };
        s.bytes[0..bytes.len()].copy_from_slice(bytes);
        Ok(s)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes.as_slice()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Signature {}

impl Debug for Signature {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        fmt.debug_list().entries(self.as_bytes().iter()).finish()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.as_bytes()
    }
}

impl LowerHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl UpperHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", self)
    }
}
