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
    components::Components, signing_key::SigningKey, size::KeySize, verifying_key::VerifyingKey,
};

pub use num_bigint::BigUint;
pub use pkcs8;
pub use signature;

use pkcs8::spki::ObjectIdentifier;

mod components;
mod generate;
mod signing_key;
mod size;
mod verifying_key;

/// DSA object identifier as defined by [RFC3279 § 2.3.2].
///
/// [RFC3279 2.3.2]: https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

use alloc::{boxed::Box, vec::Vec};
use num_traits::Zero;
use pkcs8::der::{
    self, asn1::UintRef, Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader,
    Sequence, Writer,
};
use signature::SignatureEncoding;

/// Container of the DSA signature
#[derive(Clone, Debug)]
#[must_use]
pub struct Signature {
    /// Signature part r
    r: BigUint,

    /// Signature part s
    s: BigUint,
}

impl Signature {
    /// Create a new Signature container from its components
    pub fn from_components(r: BigUint, s: BigUint) -> signature::Result<Self> {
        if r.is_zero() || s.is_zero() {
            return Err(signature::Error::new());
        }

        Ok(Self { r, s })
    }

    /// Signature part r
    #[must_use]
    pub fn r(&self) -> &BigUint {
        &self.r
    }

    /// Signature part s
    #[must_use]
    pub fn s(&self) -> &BigUint {
        &self.s
    }
}

impl<'a> DecodeValue<'a> for Signature {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let r = UintRef::decode(reader)?;
            let s = UintRef::decode(reader)?;

            let r = BigUint::from_bytes_be(r.as_bytes());
            let s = BigUint::from_bytes_be(s.as_bytes());

            Self::from_components(r, s).map_err(|_| der::Tag::Integer.value_error())
        })
    }
}

impl EncodeValue for Signature {
    fn value_len(&self) -> der::Result<Length> {
        UintRef::new(&self.r.to_bytes_be())?.encoded_len()?
            + UintRef::new(&self.s.to_bytes_be())?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        UintRef::new(&self.r.to_bytes_be())?.encode(writer)?;
        UintRef::new(&self.s.to_bytes_be())?.encode(writer)?;
        Ok(())
    }
}

impl From<Signature> for Box<[u8]> {
    fn from(sig: Signature) -> Box<[u8]> {
        sig.to_bytes()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.r().eq(other.r()) && self.s().eq(other.s())
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        (self.r(), self.s()).partial_cmp(&(other.r(), other.s()))
    }
}

impl<'a> Sequence<'a> for Signature {}

impl SignatureEncoding for Signature {
    type Repr = Box<[u8]>;

    fn to_bytes(&self) -> Box<[u8]> {
        SignatureEncoding::to_vec(self).into_boxed_slice()
    }

    fn to_vec(&self) -> Vec<u8> {
        self.to_der().expect("DER encoding error")
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        // TODO(tarcieri): capture error source when `std` feature enabled
        Self::from_der(bytes).map_err(|_| signature::Error::new())
    }
}

/// Returns a `BigUint` with the value 2
#[inline]
fn two() -> BigUint {
    BigUint::from(2_u8)
}
