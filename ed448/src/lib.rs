#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![allow(non_snake_case)]
#![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! # Using Ed448 generically over algorithm implementations/providers
//!
//! By using the `ed448-signature` crate, you can write code which signs and verifies
//! messages using the Ed448 signature algorithm generically over any
//! supported Ed448 implementation (see the next section for available
//! providers).
//!
//! This allows consumers of your code to plug in whatever implementation they
//! want to use without having to add all potential Ed448 libraries you'd
//! like to support as optional dependencies.
//!
//! ## Example
//!
//! ```
//! use ed448_signature::signature::{Signer, Verifier};
//!
//! pub struct HelloSigner<S>
//! where
//!     S: Signer<ed448_signature::Signature>
//! {
//!     pub signing_key: S
//! }
//!
//! impl<S> HelloSigner<S>
//! where
//!     S: Signer<ed448_signature::Signature>
//! {
//!     pub fn sign(&self, person: &str) -> ed448_signature::Signature {
//!         // NOTE: use `try_sign` if you'd like to be able to handle
//!         // errors from external signing services/devices (e.g. HSM/KMS)
//!         // <https://docs.rs/signature/latest/signature/trait.Signer.html#tymethod.try_sign>
//!         self.signing_key.sign(format_message(person).as_bytes())
//!     }
//! }
//!
//! pub struct HelloVerifier<V> {
//!     pub verifying_key: V
//! }
//!
//! impl<V> HelloVerifier<V>
//! where
//!     V: Verifier<ed448_signature::Signature>
//! {
//!     pub fn verify(
//!         &self,
//!         person: &str,
//!         signature: &ed448_signature::Signature
//!     ) -> Result<(), ed448_signature::Error> {
//!         self.verifying_key.verify(format_message(person).as_bytes(), signature)
//!     }
//! }
//!
//! fn format_message(person: &str) -> String {
//!     format!("Hello, {}!", person)
//! }
//! ```

mod hex;

#[cfg(feature = "pkcs8")]
pub mod pkcs8;

#[cfg(feature = "serde")]
mod serde;

pub use signature::{self, Error, SignatureEncoding};

use core::fmt;

/// Size of a single component of an Ed448 signature.
const COMPONENT_SIZE: usize = 57;

/// Size of an `R` or `s` component of an Ed448 signature when serialized
/// as bytes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ComponentBytes([u8; COMPONENT_SIZE]);

impl Default for ComponentBytes {
    fn default() -> Self {
        ComponentBytes([0; COMPONENT_SIZE])
    }
}

/// Ed448 signature serialized as a byte array.
pub type SignatureBytes = [u8; Signature::BYTE_SIZE];

/// Ed448 signature.
///
/// This type represents a container for the byte serialization of an Ed448
/// signature, and does not necessarily represent well-formed field or curve
/// elements.
///
/// Signature verification libraries are expected to reject invalid field
/// elements at the time a signature is verified.
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct Signature {
    R: ComponentBytes,
    s: ComponentBytes,
}

impl Signature {
    /// Size of an encoded Ed448 signature in bytes.
    pub const BYTE_SIZE: usize = COMPONENT_SIZE * 2;

    /// Parse an Ed448 signature from a byte slice.
    pub fn from_bytes(bytes: &SignatureBytes) -> Self {
        let mut R = ComponentBytes::default();
        let mut s = ComponentBytes::default();

        let components = bytes.split_at(COMPONENT_SIZE);
        R.0.copy_from_slice(components.0);
        s.0.copy_from_slice(components.1);

        Self { R, s }
    }

    /// Parse an Ed448 signature from a byte slice.
    ///
    /// # Returns
    /// - `Ok` on success
    /// - `Err` if the input byte slice is not 64-bytes
    pub fn from_slice(bytes: &[u8]) -> signature::Result<Self> {
        SignatureBytes::try_from(bytes)
            .map(Into::into)
            .map_err(|_| Error::new())
    }

    /// Bytes for the `R` component of a signature.
    pub fn r_bytes(&self) -> &ComponentBytes {
        &self.R
    }

    /// Bytes for the `s` component of a signature.
    pub fn s_bytes(&self) -> &ComponentBytes {
        &self.s
    }

    /// Return the inner byte array.
    pub fn to_bytes(&self) -> SignatureBytes {
        let mut ret = [0u8; Self::BYTE_SIZE];
        let (R, s) = ret.split_at_mut(COMPONENT_SIZE);
        R.copy_from_slice(&self.R.0);
        s.copy_from_slice(&self.s.0);
        ret
    }
}

impl From<Signature> for SignatureBytes {
    fn from(sig: Signature) -> SignatureBytes {
        sig.to_bytes()
    }
}

impl From<&Signature> for SignatureBytes {
    fn from(sig: &Signature) -> SignatureBytes {
        sig.to_bytes()
    }
}

impl From<SignatureBytes> for Signature {
    fn from(bytes: SignatureBytes) -> Self {
        Signature::from_bytes(&bytes)
    }
}

impl From<&SignatureBytes> for Signature {
    fn from(bytes: &SignatureBytes) -> Self {
        Signature::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Self::from_slice(bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ed448_signature::Signature")
            .field("R", self.r_bytes())
            .field("s", self.s_bytes())
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}
