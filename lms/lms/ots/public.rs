//! Contains the [PublicKey] type

use crate::constants::ID_LEN;
use crate::error::LmsDeserializeError;
use crate::ots::modes::LmsOtsMode;
use crate::ots::signature::Signature;

use crate::types::Identifier;
use digest::{Output, OutputSizeUser};

use generic_array::{ArrayLength, GenericArray};
use signature::{Error, Verifier};
use std::cmp::Ordering;
use std::ops::Add;
use typenum::{Sum, U2, U24};

#[derive(Debug)]
/// Opaque struct representing a LM-OTS public key
pub struct PublicKey<Mode: LmsOtsMode> {
    pub(crate) q: u32,
    pub(crate) id: Identifier,
    pub(crate) k: Output<Mode::Hasher>,
}

// manual Clone impl because Mode is not Clone
impl<Mode: LmsOtsMode> Clone for PublicKey<Mode> {
    fn clone(&self) -> Self {
        Self {
            q: self.q,
            id: self.id,
            k: self.k.clone(),
        }
    }
}

// manual PartialEq impl because Mode is not PartialEq
impl<Mode: LmsOtsMode> PartialEq for PublicKey<Mode> {
    fn eq(&self, other: &Self) -> bool {
        self.q == other.q && self.id == other.id && self.k == other.k
    }
}

impl<Mode: LmsOtsMode> Verifier<Signature<Mode>> for PublicKey<Mode>
where
    // required to concat Q and cksm(Q)
    <Mode::Hasher as OutputSizeUser>::OutputSize: Add<U2>,
    Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U2>: ArrayLength<u8>,
{
    // this implements algorithm 4a of https://datatracker.ietf.org/doc/html/rfc8554#section-4.6
    fn verify(&self, msg: &[u8], signature: &Signature<Mode>) -> Result<(), Error> {
        // If the public key is not at least four bytes long, return INVALID.
        // We are calling this method on a valid public key so there's no worry here.
        let kc = signature.recover_pubkey(self.id, self.q, msg);
        // 4. If Kc is equal to K, return VALID; otherwise, return INVALID.
        if self.k == kc.k {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

/// Converts a [PublicKey] into its byte representation
impl<Mode: LmsOtsMode> From<PublicKey<Mode>>
    for GenericArray<u8, Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>>
where
    <Mode::Hasher as OutputSizeUser>::OutputSize: Add<U24>,
    Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>: ArrayLength<u8>,
{
    fn from(pk: PublicKey<Mode>) -> Self {
        // Return u32str(type) || I || u32str(q) || K
        GenericArray::from_exact_iter(
            std::iter::empty()
                .chain(Mode::TYPECODE.to_be_bytes())
                .chain(pk.id)
                .chain(pk.q.to_be_bytes())
                .chain(pk.k),
        )
        .expect("ok")
    }
}

/// Tries to parse a [PublicKey] from an exact slice
impl<'a, Mode: LmsOtsMode> TryFrom<&'a [u8]> for PublicKey<Mode> {
    type Error = LmsDeserializeError;

    fn try_from(pk: &'a [u8]) -> Result<Self, Self::Error> {
        if pk.len() < 4 {
            return Err(LmsDeserializeError::NoAlgorithm);
        }

        let (alg, pk) = pk.split_at(4);
        let expected = Mode::N + ID_LEN + 4;

        // will never panic because alg is a 4 byte slice
        if u32::from_be_bytes(alg.try_into().unwrap()) != Mode::TYPECODE {
            return Err(LmsDeserializeError::WrongAlgorithm);
        }

        match pk.len().cmp(&expected) {
            Ordering::Less => Err(LmsDeserializeError::TooShort),
            Ordering::Greater => Err(LmsDeserializeError::TooLong),
            Ordering::Equal => {
                // pk is now guaranteed to be of the form I || q || K
                let (i, qk) = pk.split_at(ID_LEN);
                let (q, k) = qk.split_at(4);

                Ok(Self {
                    q: u32::from_be_bytes(q.try_into().expect("ok")),
                    id: i.try_into().expect("ok"),
                    k: GenericArray::clone_from_slice(k),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::ID_LEN;
    use crate::error::LmsDeserializeError;
    use crate::ots::modes::{LmsOtsSha256N32W4, LmsOtsSha256N32W8};
    use crate::ots::private::PrivateKey;
    use crate::ots::public::PublicKey;
    use generic_array::GenericArray;
    use rand::thread_rng;

    #[test]
    fn test_serde() {
        let pk =
            PrivateKey::<LmsOtsSha256N32W8>::new(0, [0xbb; ID_LEN], &mut thread_rng()).public();
        let pk_serialized: GenericArray<u8, _> = pk.clone().into();
        let bytes = pk_serialized.as_slice();
        let pk_deserialized = PublicKey::<LmsOtsSha256N32W8>::try_from(bytes);

        assert!(pk_deserialized.is_ok());
        let pk_deserialized = pk_deserialized.unwrap();
        assert_eq!(pk, pk_deserialized);

        let pk_wrongalgo = PublicKey::<LmsOtsSha256N32W4>::try_from(bytes);
        let pk_short = PublicKey::<LmsOtsSha256N32W8>::try_from(&bytes[0..(bytes.len() - 1)]);
        let mut long_bytes = pk_serialized.into_iter().collect::<Vec<_>>();
        long_bytes.push(0);
        let pk_long = PublicKey::<LmsOtsSha256N32W8>::try_from(long_bytes.as_slice());

        assert_eq!(pk_wrongalgo, Err(LmsDeserializeError::WrongAlgorithm));
        assert_eq!(pk_short, Err(LmsDeserializeError::TooShort));
        assert_eq!(pk_long, Err(LmsDeserializeError::TooLong));
    }
}
