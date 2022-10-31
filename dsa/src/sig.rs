//!
//! Module containing the definition of the Signature container
//!

use alloc::{boxed::Box, vec::Vec};
use num_bigint::BigUint;
use num_traits::Zero;
use pkcs8::der::{self, asn1::UIntRef, Decode, Encode, Reader, Sequence};
use signature::SignatureEncoding;

/// Container of the DSA signature
#[derive(Clone)]
#[must_use]
pub struct Signature {
    /// Signature part r
    r: BigUint,

    /// Signature part s
    s: BigUint,
}

opaque_debug::implement!(Signature);

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

impl<'a> Decode<'a> for Signature {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        reader.sequence(|sequence| {
            let r = UIntRef::decode(sequence)?;
            let s = UIntRef::decode(sequence)?;

            let r = BigUint::from_bytes_be(r.as_bytes());
            let s = BigUint::from_bytes_be(s.as_bytes());

            Self::from_components(r, s).map_err(|_| der::Tag::Integer.value_error())
        })
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

impl<'a> Sequence<'a> for Signature {
    fn fields<F, T>(&self, encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encode]) -> der::Result<T>,
    {
        let r_bytes = self.r.to_bytes_be();
        let s_bytes = self.s.to_bytes_be();

        let r = UIntRef::new(&r_bytes)?;
        let s = UIntRef::new(&s_bytes)?;

        encoder(&[&r, &s])
    }
}

impl SignatureEncoding for Signature {
    type Repr = Box<[u8]>;

    fn to_bytes(&self) -> Box<[u8]> {
        self.to_boxed_slice()
    }

    fn to_vec(&self) -> Vec<u8> {
        Encode::to_vec(self).expect("DER encoding error")
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        // TODO(tarcieri): capture error source when `std` feature enabled
        Self::from_der(bytes).map_err(|_| signature::Error::new())
    }
}
