//!
//! Module containing the definition of the signature container
//!

use num_bigint::BigUint;
use pkcs8::der::{self, asn1::UIntRef, Decode, Decoder, Reader, Sequence};

/// Container of the DSA signature
#[derive(Clone, PartialEq, PartialOrd)]
#[must_use]
pub struct Signature {
    /// Signature part r
    r: BigUint,

    /// Signature part s
    s: BigUint,
}

opaque_debug::implement!(Signature);

impl Signature {
    /// Create a new signature container from its components
    pub fn new(r: BigUint, s: BigUint) -> Self {
        Self { r, s }
    }

    /// Decode a signature from its DER representation
    ///
    /// # Errors
    ///
    /// See the [`der` errors](pkcs8::der::Error)
    pub fn from_der(data: &[u8]) -> der::Result<Self> {
        let mut reader = Decoder::new(data)?;
        reader.decode()
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
        let r = reader.decode::<UIntRef<'_>>()?;
        let s = reader.decode::<UIntRef<'_>>()?;

        let r = BigUint::from_bytes_be(r.as_bytes());
        let s = BigUint::from_bytes_be(s.as_bytes());

        Ok(Self::new(r, s))
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
