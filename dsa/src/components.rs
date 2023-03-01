//!
//! Module containing the definition of the common components container
//!

use crate::{size::KeySize, two};
use num_bigint::BigUint;
use num_traits::Zero;
use pkcs8::der::{
    self, asn1::UintRef, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Tag,
    Writer,
};
use signature::rand_core::CryptoRngCore;

/// The common components of an DSA keypair
///
/// (the prime p, quotient q and generator g)
#[derive(Clone, Debug, PartialEq, PartialOrd)]
#[must_use]
pub struct Components {
    /// Prime p
    p: BigUint,

    /// Quotient q
    q: BigUint,

    /// Generator g
    g: BigUint,
}

impl Components {
    /// Construct the common components container from its inner values (p, q and g)
    pub fn from_components(p: BigUint, q: BigUint, g: BigUint) -> signature::Result<Self> {
        if p < two() || q < two() || g.is_zero() || g > p {
            return Err(signature::Error::new());
        }

        Ok(Self { p, q, g })
    }

    /// Generate a new pair of common components
    pub fn generate(rng: &mut impl CryptoRngCore, key_size: KeySize) -> Self {
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
}

impl<'a> DecodeValue<'a> for Components {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let p = reader.decode::<UintRef<'_>>()?;
        let q = reader.decode::<UintRef<'_>>()?;
        let g = reader.decode::<UintRef<'_>>()?;

        let p = BigUint::from_bytes_be(p.as_bytes());
        let q = BigUint::from_bytes_be(q.as_bytes());
        let g = BigUint::from_bytes_be(g.as_bytes());

        Self::from_components(p, q, g).map_err(|_| Tag::Integer.value_error())
    }
}

impl EncodeValue for Components {
    fn value_len(&self) -> der::Result<Length> {
        UintRef::new(&self.p.to_bytes_be())?.encoded_len()?
            + UintRef::new(&self.q.to_bytes_be())?.encoded_len()?
            + UintRef::new(&self.g.to_bytes_be())?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        UintRef::new(&self.p.to_bytes_be())?.encode(writer)?;
        UintRef::new(&self.q.to_bytes_be())?.encode(writer)?;
        UintRef::new(&self.g.to_bytes_be())?.encode(writer)?;
        Ok(())
    }
}

impl<'a> Sequence<'a> for Components {}
