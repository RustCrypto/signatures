#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

//!
//! # Examples
//!
//! Generate a DSA keypair
//!
//! ```
//! # use dsa::{KeySize, Components, SigningKey};
//! let mut csprng = rand::thread_rng();
//! let components = Components::generate(&mut csprng, KeySize::DSA_2048_256);
//! let signing_key = SigningKey::generate(&mut csprng, components);
//! let verifying_key = signing_key.verifying_key();
//! ```
//!
//! Create keypair from existing components
//!
//! ```
//! # use dsa::{Components, SigningKey, VerifyingKey};
//! # use num_bigint::BigUint;
//! # use num_traits::One;
//! # let read_common_parameters = || (BigUint::one(), BigUint::one(), BigUint::one());
//! # let read_public_component = || BigUint::one();
//! # let read_private_component = || BigUint::one();
//! # || -> signature::Result<()> {
//! let (p, q, g) = read_common_parameters();
//! let components = Components::from_components(p, q, g)?;
//!
//! let x = read_public_component();
//! let verifying_key = VerifyingKey::from_components(components, x)?;
//!
//! let y = read_private_component();
//! let signing_key = SigningKey::from_components(verifying_key, y)?;
//!
//! # Ok(())
//! # }();
//! ```
//!

extern crate alloc;

pub use crate::{
    components::Components, sig::Signature, signing_key::SigningKey, size::KeySize,
    verifying_key::VerifyingKey,
};

pub use num_bigint::BigUint;
pub use pkcs8;
pub use signature;

use pkcs8::spki::ObjectIdentifier;

mod components;
mod generate;
mod sig;
mod signing_key;
mod size;
mod verifying_key;

/// DSA object identifier as defined by RFC-3279, section 2.3.2
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

/// Returns a `BigUint` with the value 2
#[inline]
fn two() -> BigUint {
    BigUint::from(2_u8)
}
