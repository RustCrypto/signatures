#![no_std]
#![forbid(missing_docs, unsafe_code)]
#![deny(rust_2018_idioms)]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

//!
//! Generate a DSA keypair
//!
//! ```
//! # use dsa::{consts::DSA_2048_256, Components, PrivateKey};
//! let mut csprng = rand::thread_rng();
//! let components = Components::generate(&mut csprng, DSA_2048_256);
//! let private_key = PrivateKey::generate(&mut csprng, components);
//! let public_key = private_key.public_key();
//! ```
//!
//! Create keypair from existing components
//!
//! ```
//! # use dsa::{Components, PrivateKey, PublicKey};
//! # use num_bigint::BigUint;
//! # use num_traits::One;
//! # let read_common_parameters = || (BigUint::one(), BigUint::one(), BigUint::one());
//! # let read_public_component = || BigUint::one();
//! # let read_private_component = || BigUint::one();
//! let (p, q, g) = read_common_parameters();
//! let components = Components::from_components(p, q, g);
//!
//! let x = read_public_component();
//! let public_key = PublicKey::from_components(components, x);
//!
//! let y = read_private_component();
//! let private_key = PrivateKey::from_components(public_key, y);
//! ```
//!

extern crate alloc;

/// DSA object identifier as defined by RFC-3279, section 2.3.2
const DSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

pub use self::components::Components;
pub use self::privatekey::PrivateKey;
pub use self::publickey::PublicKey;
pub use self::sig::Signature;

pub use pkcs8;
pub use signature;

pub mod consts;

use num_bigint::BigUint;
use pkcs8::spki::ObjectIdentifier;

mod components;
mod generate;
mod privatekey;
mod publickey;
mod sig;

/// Returns a `BigUint` with the value 2
#[inline]
fn two() -> BigUint {
    BigUint::from(2_u8)
}
