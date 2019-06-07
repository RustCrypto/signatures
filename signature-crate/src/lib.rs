//! Traits which provide generic, object-safe APIs for generating and verifying
//! digital signatures, which provide message authentication using public-key
//! cryptography.

#![no_std]
#![deny(
    warnings,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications
)]
#![doc(html_root_url = "https://docs.rs/signature/0.2.0")]

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[allow(unused_imports)] // rustc bug?
#[macro_use]
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
mod prelude;
mod signature;
mod signer;
mod verifier;

pub use crate::{error::*, signature::*, signer::*, verifier::*};
