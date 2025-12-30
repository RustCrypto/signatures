#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
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
//! use getrandom::rand_core::TryRngCore;
//!
//! let mut csprng = getrandom::SysRng.unwrap_err();
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
pub use signature;

#[cfg(feature = "pkcs8")]
pub use pkcs8;

use crypto_bigint::NonZero;

mod components;
mod generate;
mod signing_key;
mod size;
mod verifying_key;

use alloc::{boxed::Box, vec::Vec};
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Length, Reader, Sequence, Writer,
    asn1::UintRef,
};
use signature::SignatureEncoding;

#[cfg(feature = "pkcs8")]
use pkcs8::ObjectIdentifier;

/// DSA object identifier as defined by [RFC3279 § 2.3.2].
///
/// [RFC3279 2.3.2]: https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2
#[cfg(feature = "pkcs8")]
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

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
}

impl<'a> DecodeValue<'a> for Signature {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let r = UintRef::decode(reader)?;
        let s = UintRef::decode(reader)?;

        let r = BoxedUint::from_be_slice(r.as_bytes(), r.as_bytes().len() as u32 * 8)
            .map_err(|_| UintRef::TAG.value_error())?;
        let s = BoxedUint::from_be_slice(s.as_bytes(), s.as_bytes().len() as u32 * 8)
            .map_err(|_| UintRef::TAG.value_error())?;

        Self::from_components(r, s).ok_or_else(|| reader.error(UintRef::TAG.value_error()))
    }
}

impl EncodeValue for Signature {
    fn value_len(&self) -> der::Result<Length> {
        UintRef::new(&self.r.to_be_bytes())?.encoded_len()?
            + UintRef::new(&self.s.to_be_bytes())?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        UintRef::new(&self.r.to_be_bytes())?.encode(writer)?;
        UintRef::new(&self.s.to_be_bytes())?.encode(writer)?;
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

impl Sequence<'_> for Signature {}

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
        Self::from_der(bytes).map_err(signature::Error::from_source)
    }
}

/// Returns a `BoxedUint` with the value 2
#[inline]
fn two() -> BoxedUint {
    BoxedUint::from(2_u8)
}
