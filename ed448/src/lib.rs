#![no_std]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case)]
#![forbid(unsafe_code)]

mod hex;

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

    /// Bytes for the `R` component of a signature.
    pub fn r_bytes(&self) -> &ComponentBytes {
        &self.R
    }

    /// Bytes for the `s` component of a signature.
    pub fn s_bytes(&self) -> &ComponentBytes {
        &self.s
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ed448::Signature")
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
