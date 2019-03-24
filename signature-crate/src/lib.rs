//! Digital signature types and traits

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

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

mod error;
pub(crate) mod prelude;
mod signature;

pub use crate::{error::Error, signature::Signature};
