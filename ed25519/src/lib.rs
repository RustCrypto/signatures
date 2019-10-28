//! Ed25519 signatures.
//!
//! Edwards Digital Signature Algorithm (EdDSA) over Curve25519 as specified in
//! RFC 8032: <https://tools.ietf.org/html/rfc8032>
//!
//! This crate doesn't contain an implementation of Ed25519, but instead
//! contains an [`ed25519::Signature`] type which other crates can use in
//! conjunction with the [`signature::Signer`] and [`signature::Verifier`]
//! traits.
//!
//! These traits allow crates which produce and consume Ed25519 signatures
//! to be written abstractly in such a way that different signer/verifier
//! providers can be plugged in, enabling support for using different
//! Ed25519 implementations, including HSMs or Cloud KMS services.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png",
    html_root_url = "https://docs.rs/ed25519/1.0.0-pre.1"
)]

#[cfg(feature = "serde")]
use serde::{de, ser, Deserialize, Serialize};

/// Re-export the `signature` crate
pub use signature::{self, Error};

use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
};

/// Length of an Ed25519 signature
pub const SIGNATURE_LENGTH: usize = 64;

/// Ed25519 signature.
#[derive(Copy, Clone)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    /// Create a new signature from a byte array
    pub fn new(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self::from(bytes)
    }

    /// Return the inner byte array
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// can't derive `Debug`, `PartialEq`, or `Eq` below because core array types
// only have  trait implementations for lengths 0..=32
// TODO(tarcieri): derive `PartialEq` and `Eq` after const generics are available
impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519::Signature({:?})", &self.0[..])
    }
}

impl Eq for Signature {}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for Signature {
    fn from(bytes: [u8; SIGNATURE_LENGTH]) -> Signature {
        Signature(bytes)
    }
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        // can't use `try_from` ourselves here because core array types only
        // have TryFrom trait implementations for lengths 0..=32
        // TODO(tarcieri): switch to `TryFrom` after const generics are available
        if bytes.len() == SIGNATURE_LENGTH {
            let mut arr = [0u8; SIGNATURE_LENGTH];
            arr.copy_from_slice(bytes);
            Ok(Signature(arr))
        } else {
            Err(Error::new())
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Signature {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(serializer)
    }
}

// serde lacks support for deserializing arrays larger than 32-bytes
// see: <https://github.com/serde-rs/serde/issues/631>
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ByteArrayVisitor;

        impl<'de> de::Visitor<'de> for ByteArrayVisitor {
            type Value = [u8; SIGNATURE_LENGTH];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bytestring of length 64")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; SIGNATURE_LENGTH], A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                use de::Error;
                let mut arr = [0u8; SIGNATURE_LENGTH];

                for i in 0..SIGNATURE_LENGTH {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }

                Ok(arr)
            }
        }

        deserializer
            .deserialize_tuple(SIGNATURE_LENGTH, ByteArrayVisitor)
            .map(|bytes| bytes.into())
    }
}
