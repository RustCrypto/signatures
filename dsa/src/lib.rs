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
#![cfg_attr(feature = "hazmat", doc = "```")]
#![cfg_attr(not(feature = "hazmat"), doc = "```ignore")]
//! # use dsa::{KeySize, Components, SigningKey};
//! let mut csprng = rand::thread_rng();
//! let components = Components::generate(&mut csprng, KeySize::DSA_2048_256);
//! let signing_key = SigningKey::generate(&mut csprng, components);
//! let verifying_key = signing_key.verifying_key();
//! ```
//!
//! Create keypair from existing components
//!
#![cfg_attr(feature = "hazmat", doc = "```")]
#![cfg_attr(not(feature = "hazmat"), doc = "```ignore")]
//! # use dsa::{Components, SigningKey, VerifyingKey};
//! # use crypto_bigint::{BoxedUint, NonZero, Odd};
//! # let read_common_parameters = ||
//! #     (
//! #          BoxedUint::one(),
//! #          BoxedUint::one(),
//! #          BoxedUint::one(),
//! #     );
//! # let read_public_component = || BoxedUint::one();
//! # let read_private_component = || BoxedUint::one();
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

#[cfg(feature = "hazmat")]
pub use crate::signing_key::SigningKey;

pub use crate::{components::Components, size::KeySize, verifying_key::VerifyingKey};

pub use crypto_bigint::BoxedUint;
pub use pkcs8;
pub use signature;

use crypto_bigint::NonZero;
use pkcs8::spki::ObjectIdentifier;

mod components;
mod generate;
mod signature_ref;
mod signing_key;
mod size;
mod verifying_key;

/// DSA object identifier as defined by [RFC3279 § 2.3.2].
///
/// [RFC3279 2.3.2]: https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

use alloc::{boxed::Box, vec::Vec};
use pkcs8::der::{
    self, Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Writer,
};
use signature::SignatureEncoding;
use signature_ref::{SignatureBoxed, SignatureRef};

/// Container of the DSA signature
#[derive(Clone, Debug)]
#[must_use]
pub struct Signature {
    /// Signature part r
    r: NonZero<BoxedUint>,

    /// Signature part s
    s: NonZero<BoxedUint>,
}

impl Signature {
    /// Create a new Signature container from its components
    pub fn from_components(r: BoxedUint, s: BoxedUint) -> Option<Self> {
        let r = NonZero::new(r).into_option()?;
        let s = NonZero::new(s).into_option()?;
        Some(Self { r, s })
    }

    /// Signature part r
    #[must_use]
    pub fn r(&self) -> &NonZero<BoxedUint> {
        &self.r
    }

    /// Signature part s
    #[must_use]
    pub fn s(&self) -> &NonZero<BoxedUint> {
        &self.s
    }

    fn to_boxed(&self) -> SignatureBoxed {
        SignatureBoxed::new(self)
    }
    fn to_der_using_ref(&self) -> der::Result<Vec<u8>> {
        self.to_boxed().to_ref()?.to_der()
    }
}

impl<'a> DecodeValue<'a> for Signature {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let signature_ref = SignatureRef::decode_value(reader, header)?;

        signature_ref.to_owned()
    }
}

impl EncodeValue for Signature {
    fn value_len(&self) -> der::Result<Length> {
        // TODO: avoid Box<[u8]> allocation here
        self.to_boxed().to_ref()?.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.to_boxed().to_ref()?.encode_value(writer)
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

impl Sequence<'_> for Signature {}

impl SignatureEncoding for Signature {
    type Repr = Box<[u8]>;

    fn to_bytes(&self) -> Box<[u8]> {
        SignatureEncoding::to_vec(self).into_boxed_slice()
    }

    fn to_vec(&self) -> Vec<u8> {
        self.to_der_using_ref().expect("DER encoding error")
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Self::from_der(bytes).map_err(signature::Error::from_source)
    }
}

/// Returns a `BoxedUint` with the value 2
#[inline]
fn two() -> BoxedUint {
    BoxedUint::from(2_u8)
}
