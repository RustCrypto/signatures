use alloc::boxed::Box;
use crypto_bigint::{BoxedUint, NonZero};
use pkcs8::der::{
    self, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence,
    Writer, asn1::UintRef,
};

use crate::Signature;

pub(crate) struct SignatureBoxed {
    r: Box<[u8]>,
    s: Box<[u8]>,
}
impl SignatureBoxed {
    pub fn new(sig: &Signature) -> Self {
        Self {
            r: sig.r().to_be_bytes(),
            s: sig.s().to_be_bytes(),
        }
    }

    pub fn to_ref(&self) -> der::Result<SignatureRef<'_>> {
        Ok(SignatureRef {
            r: UintRef::new(&self.r)?,
            s: UintRef::new(&self.s)?,
        })
    }
}

pub(crate) struct SignatureRef<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}
impl<'a> SignatureRef<'a> {
    pub fn to_owned(&self) -> der::Result<Signature> {
        let r = BoxedUint::from_be_slice(self.r.as_bytes(), self.r.as_bytes().len() as u32 * 8)
            .map_err(|_| UintRef::TAG.value_error())?;
        let s = BoxedUint::from_be_slice(self.s.as_bytes(), self.s.as_bytes().len() as u32 * 8)
            .map_err(|_| UintRef::TAG.value_error())?;

        let r = NonZero::new(r)
            .into_option()
            .ok_or(UintRef::TAG.value_error())?;
        let s = NonZero::new(s)
            .into_option()
            .ok_or(UintRef::TAG.value_error())?;

        Ok(Signature::from_components(r, s))
    }
}

impl<'a> DecodeValue<'a> for SignatureRef<'a> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        Ok(SignatureRef {
            r: UintRef::decode(reader)?,
            s: UintRef::decode(reader)?,
        })
    }
}

impl EncodeValue for SignatureRef<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.r.encoded_len()? + self.s.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.r.encode(writer)?;
        self.s.encode(writer)?;
        Ok(())
    }
}
impl<'a> Sequence<'a> for SignatureRef<'a> {}
