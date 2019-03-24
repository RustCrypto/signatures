//! Digital signature types and traits

#![crate_name = "signature"]
#![crate_type = "lib"]
#![no_std]
#![cfg_attr(all(feature = "nightly", not(feature = "std")), feature(alloc))]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

mod error;
pub(crate) mod prelude;
mod signature;

pub use error::Error;
pub use signature::Signature;
