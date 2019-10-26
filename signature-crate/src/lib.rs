//! Traits which provide generic, object-safe APIs for generating and verifying
//! digital signatures, which provide message authentication using public-key
//! cryptography.
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.31** or higher.
//!
//! Minimum supported Rust version can be changed in the future, but it will be
//! done with a minor version bump.
//!
//! ## SemVer Policy
//!
//! - All on-by-default features of this library are covered by SemVer
//! - MSRV is considered exempt from SemVer as noted above
//! - The off-by-default features `derive-preview` and `digest-preview` are
//!   unstable "preview" features which are also considered exempt from SemVer.
//!   Breaking changes to these features will, like MSRV, be done with a minor
//!   version bump.

#![no_std]
#![doc(html_root_url = "https://docs.rs/signature/1.0.0-pre.0")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "derive-preview")]
#[allow(unused_imports)]
#[macro_use]
extern crate signature_derive;

#[cfg(feature = "derive-preview")]
#[doc(hidden)]
pub use signature_derive::{Signer, Verifier};

#[cfg(feature = "digest-preview")]
pub use digest;

mod error;
mod signature;
mod signer;
mod verifier;

pub use crate::{error::*, signature::*, signer::*, verifier::*};
