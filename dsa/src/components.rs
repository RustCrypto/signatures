//!
//! Module containing the definition of the common components container
//!

use crate::{size::KeySize, two};
use crypto_bigint::{BoxedUint, NonZero, Odd};
use der::{
    self, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Tag, Writer,
    asn1::UintRef,
};
use signature::rand_core::CryptoRng;

/// The common components of an DSA keypair
///
/// (the prime p, quotient q and generator g)
#[derive(Clone, Debug, PartialEq, PartialOrd)]
#[must_use]
pub struct Components {
    /// Prime p
    p: Odd<BoxedUint>,

    /// Quotient q
    q: NonZero<BoxedUint>,

    /// Generator g
    g: NonZero<BoxedUint>,

    pub(crate) key_size: KeySize,
}

impl Components {
    /// Construct the common components container from its inner values (p, q and g)
    pub fn from_components(p: BoxedUint, q: BoxedUint, g: BoxedUint) -> signature::Result<Self> {
        let (p, q, g) = Self::adapt_components(p, q, g)?;

        let key_size = match (p.bits_precision(), q.bits_precision()) {
            #[allow(deprecated)]
            (p, q) if KeySize::DSA_1024_160.matches(p, q) => KeySize::DSA_1024_160,
            (p, q) if KeySize::DSA_2048_224.matches(p, q) => KeySize::DSA_2048_224,
            (p, q) if KeySize::DSA_2048_256.matches(p, q) => KeySize::DSA_2048_256,
            (p, q) if KeySize::DSA_3072_256.matches(p, q) => KeySize::DSA_3072_256,
            _ => return Err(signature::Error::new()),
        };

        Ok(Self { p, q, g, key_size })
    }

    /// Construct the common components container from its inner values (p, q and g)
    ///
    /// # Safety
    ///
    /// Any length of keys may be used, no checks are to be performed. You are responsible for
    /// checking the key strengths.
    #[cfg(feature = "hazmat")]
    pub fn from_components_unchecked(
        p: BoxedUint,
        q: BoxedUint,
        g: BoxedUint,
    ) -> signature::Result<Self> {
        let (p, q, g) = Self::adapt_components(p, q, g)?;
        let key_size = KeySize::other(p.bits_precision(), q.bits_precision());

        Ok(Self { p, q, g, key_size })
    }

    /// Helper method to build a [`Components`]
    fn adapt_components(
        p: BoxedUint,
        q: BoxedUint,
        g: BoxedUint,
    ) -> signature::Result<(Odd<BoxedUint>, NonZero<BoxedUint>, NonZero<BoxedUint>)> {
        let p = Odd::new(p)
            .into_option()
            .ok_or_else(signature::Error::new)?;
        let q = NonZero::new(q)
            .into_option()
            .ok_or_else(signature::Error::new)?;
        let g = NonZero::new(g)
            .into_option()
            .ok_or_else(signature::Error::new)?;

        if *p < two() || *q < two() || *g > *p {
            return Err(signature::Error::new());
        }

        Ok((p, q, g))
    }

    /// Generate a new pair of common components
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, key_size: KeySize) -> Self {
        let (p, q, g) = crate::generate::common_components(rng, key_size);
        Self::from_components(p.get(), q.get(), g.get())
            .expect("[Bug] Newly generated components considered invalid")
    }

    /// DSA prime p
    #[must_use]
    pub const fn p(&self) -> &Odd<BoxedUint> {
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

        let p = BoxedUint::from_be_slice_vartime(p.as_bytes());
        let q = BoxedUint::from_be_slice_vartime(q.as_bytes());
        let g = BoxedUint::from_be_slice_vartime(g.as_bytes());

        Self::from_components(p, q, g).map_err(|_| reader.error(Tag::Integer.value_error()))
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

impl Sequence<'_> for Components {}
