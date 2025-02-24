//!
//! Module containing the definition of the common components container
//!

use crate::{size::KeySize, two};
use crypto_bigint::{BoxedUint, NonZero};
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
    p: NonZero<BoxedUint>,

    /// Quotient q
    q: NonZero<BoxedUint>,

    /// Generator g
    g: NonZero<BoxedUint>,
}

impl Components {
    /// Construct the common components container from its inner values (p, q and g)
    pub fn from_components(
        p: NonZero<BoxedUint>,
        q: NonZero<BoxedUint>,
        g: NonZero<BoxedUint>,
    ) -> signature::Result<Self> {
        if *p < two() || *q < two() || g > p {
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
    pub const fn p(&self) -> &NonZero<BoxedUint> {
        &self.p
    }

    /// DSA quotient q
    #[must_use]
    pub const fn q(&self) -> &NonZero<BoxedUint> {
        &self.q
    }

    /// DSA generator g
    #[must_use]
    pub const fn g(&self) -> &NonZero<BoxedUint> {
        &self.g
    }
}

impl<'a> DecodeValue<'a> for Components {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let p = reader.decode::<UintRef<'_>>()?;
        let q = reader.decode::<UintRef<'_>>()?;
        let g = reader.decode::<UintRef<'_>>()?;

        // Just use the precision of `p` since `p` will be the largest value and all values need to have the same precision
        let precision = (p.as_bytes().len() * 8) as u32;

        let p = BoxedUint::from_be_slice(p.as_bytes(), precision).unwrap();
        let q = BoxedUint::from_be_slice(q.as_bytes(), precision).unwrap();
        let g = BoxedUint::from_be_slice(g.as_bytes(), precision).unwrap();

        let p = NonZero::new(p).unwrap();
        let q = NonZero::new(q).unwrap();
        let g = NonZero::new(g).unwrap();

        Self::from_components(p, q, g).map_err(|_| Tag::Integer.value_error())
    }
}

impl EncodeValue for Components {
    fn value_len(&self) -> der::Result<Length> {
        UintRef::new(&self.p.to_be_bytes())?.encoded_len()?
            + UintRef::new(&self.q.to_be_bytes())?.encoded_len()?
            + UintRef::new(&self.g.to_be_bytes())?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        UintRef::new(&self.p.to_be_bytes())?.encode(writer)?;
        UintRef::new(&self.q.to_be_bytes())?.encode(writer)?;
        UintRef::new(&self.g.to_be_bytes())?.encode(writer)?;
        Ok(())
    }
}

impl<'a> Sequence<'a> for Components {}
