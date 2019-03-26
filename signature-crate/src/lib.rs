//! Traits which provide generic, object-safe APIs for generating and verifying
//! digital signatures, which provide message authentication using public-key
//! cryptography.

#![no_std]
#![cfg_attr(all(feature = "nightly", not(feature = "std")), feature(alloc))]
#![deny(
    warnings,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications
)]

#[cfg(feature = "digest")]
pub extern crate digest;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

mod error;
mod prelude;
pub mod sign;
mod signature;
pub mod verify;

pub use crate::{error::Error, sign::Sign, signature::Signature, verify::Verify};
