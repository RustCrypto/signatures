//! Traits which provide generic, object-safe APIs for generating and verifying
//! digital signatures, which provide message authentication using public-key
//! cryptography.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(html_root_url = "https://docs.rs/signature/0.2.0")]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "signature_derive")]
#[allow(unused_imports)]
#[macro_use]
extern crate signature_derive;

#[cfg(feature = "signature_derive")]
#[doc(hidden)]
pub use signature_derive::{Signer, Verifier};

#[cfg(feature = "digest")]
pub use digest;

mod error;
mod signature;
mod signer;
mod verifier;

pub use crate::{error::*, signature::*, signer::*, verifier::*};
