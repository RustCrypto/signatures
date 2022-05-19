//!
//! Module containing the definition of the Signature container
//!

use alloc::vec::Vec;
use num_bigint::BigUint;
use num_traits::Zero;
use pkcs8::der::{self, asn1::UIntRef, Decode, Encode, Reader, Sequence};

use crate::Components;

/// Container of the DSA signature
#[derive(Clone)]
#[must_use]
pub struct Signature {
    /// Internally cached DER representation of the signature
    der_repr: Vec<u8>,

    /// Signature part r
    r: BigUint,

    /// Signature part s
    s: BigUint,
}

opaque_debug::implement!(Signature);

impl Signature {
    /// Create a new Signature container from its components
    pub fn from_components(r: BigUint, s: BigUint) -> Self {
        let mut signature = Self {
            der_repr: Vec::with_capacity(0),
            r,
            s,
        };
        signature.der_repr = signature.to_vec().unwrap();

        signature
    }

    /// Verify signature component validity
    pub(crate) fn r_s_valid(&self, components: &Components) -> bool {
        if self.r().is_zero()
            || self.s().is_zero()
            || self.r() > components.q()
            || self.s() > components.q()
        {
            return false;
        }

        true
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

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.der_repr
    }
}

impl<'a> Decode<'a> for Signature {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        reader.sequence(|sequence| {
            let r = UIntRef::decode(sequence)?;
            let s = UIntRef::decode(sequence)?;

            let r = BigUint::from_bytes_be(r.as_bytes());
            let s = BigUint::from_bytes_be(s.as_bytes());

            Ok(Self::from_components(r, s))
        })
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

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Signature::from_der(bytes).map_err(|_| signature::Error::new())
    }
}
