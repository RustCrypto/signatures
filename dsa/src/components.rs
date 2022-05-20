//!
//! Module containing the definition of the common components container
//!

use crate::{size::KeySize, two};
use num_bigint::BigUint;
use num_traits::One;
use pkcs8::der::{
    self, asn1::UIntRef, DecodeValue, Encode, ErrorKind, Header, Reader, Sequence, Tag,
};
use rand::{CryptoRng, RngCore};

/// The common components of an DSA keypair
///
/// (the prime p, quotient q and generator g)
#[derive(Clone, PartialEq, PartialOrd)]
#[must_use]
pub struct Components {
    /// Prime p
    p: BigUint,

    /// Quotient q
    q: BigUint,

    /// Generator g
    g: BigUint,
}

opaque_debug::implement!(Components);

impl Components {
    /// Construct the common components container from its inner values (p, q and g)
    pub fn from_components(p: BigUint, q: BigUint, g: BigUint) -> signature::Result<Self> {
        let components = Self { p, q, g };

        if !components.is_valid() {
            return Err(signature::Error::new());
        }
        Ok(components)
    }

    /// Generate a new pair of common components
    pub fn generate<R>(rng: &mut R, key_size: KeySize) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let (p, q, g) = crate::generate::common_components(rng, key_size);
        Self::from_components(p, q, g).expect("[Bug] Newly generated components considered invalid")
    }

    /// DSA prime p
    #[must_use]
    pub const fn p(&self) -> &BigUint {
        &self.p
    }

    /// DSA quotient q
    #[must_use]
    pub const fn q(&self) -> &BigUint {
        &self.q
    }

    /// DSA generator g
    #[must_use]
    pub const fn g(&self) -> &BigUint {
        &self.g
    }

    /// Check whether the components are valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        *self.p() >= two()
            && *self.q() >= two()
            && *self.g() >= BigUint::one()
            && self.g() < self.p()
    }
}

impl<'a> DecodeValue<'a> for Components {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let p = reader.decode::<UIntRef<'_>>()?;
        let q = reader.decode::<UIntRef<'_>>()?;
        let g = reader.decode::<UIntRef<'_>>()?;

        let p = BigUint::from_bytes_be(p.as_bytes());
        let q = BigUint::from_bytes_be(q.as_bytes());
        let g = BigUint::from_bytes_be(g.as_bytes());

        // TODO: Using this error doesn't seem right
        Self::from_components(p, q, g)
            .map_err(|_| der::Error::new(ErrorKind::Value { tag: Tag::Integer }, reader.position()))
    }
}

impl<'a> Sequence<'a> for Components {
    fn fields<F, T>(&self, encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        let p_bytes = self.p.to_bytes_be();
        let q_bytes = self.q.to_bytes_be();
        let g_bytes = self.g.to_bytes_be();

        let p = UIntRef::new(&p_bytes)?;
        let q = UIntRef::new(&q_bytes)?;
        let g = UIntRef::new(&g_bytes)?;

        encoder(&[&p, &q, &g])
    }
}
