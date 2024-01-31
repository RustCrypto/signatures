use std::cmp::Ordering;
use std::ops::Add;

use crate::constants::{D_LEAF, ID_LEN};

use crate::error::LmsDeserializeError;
use crate::lms::Signature;
use crate::types::Typecode;
use crate::{constants::D_INTR, lms::LmsMode};
use digest::{Digest, OutputSizeUser};
use generic_array::{ArrayLength, GenericArray};
use signature::{Error, Verifier};
use typenum::{Sum, U24};

//use crate::signature::Signature as Signature;
use crate::types::Identifier;

use digest::Output;

#[derive(Debug)]
/// Opaque struct representing a LMS public key
pub struct PublicKey<Mode: LmsMode> {
    pub(crate) id: Identifier,
    pub(crate) k: Output<Mode::Hasher>,
}

impl<Mode: LmsMode> Clone for PublicKey<Mode> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            k: self.k.clone(),
        }
    }
}

impl<Mode: LmsMode> PartialEq for PublicKey<Mode> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.k == other.k
    }
}

impl<Mode: LmsMode> PublicKey<Mode> {
    pub fn new(id: Identifier, k: Output<Mode::Hasher>) -> Self {
        Self { id, k }
    }

    /// Returns the 16-byte identifier of the public key
    pub fn id(&self) -> &Identifier {
        &self.id
    }

    /// Returns the N-byte public key as a byte slice
    pub fn k(&self) -> &[u8] {
        &self.k
    }
}

impl<Mode: LmsMode> Verifier<Signature<Mode>> for PublicKey<Mode> {
    fn verify(&self, msg: &[u8], signature: &Signature<Mode>) -> Result<(), Error> {
        // Compute the LMS Public Key Candidate Tc from the signature,
        //    message, identifier, pubtype, and ots_typecode, using
        //    Algorithm 6a.
        let key_candidate = signature
            .lmots_sig
            .recover_pubkey(self.id, signature.q, msg);

        let mut node_num = signature.q + Mode::LEAVES;
        let mut tmp = Mode::Hasher::new()
            .chain_update(self.id)
            .chain_update(node_num.to_be_bytes())
            .chain_update(D_LEAF)
            .chain_update(key_candidate.k)
            .finalize();

        for i in 0..Mode::H {
            // Tc = H(I || u32str(node_num/2) || u16str(D_INTR) || path[i] || tmp)
            let mut hasher = Mode::Hasher::new()
                .chain_update(self.id)
                .chain_update((node_num / 2).to_be_bytes())
                .chain_update(D_INTR);
            if node_num % 2 == 1 {
                hasher.update(&signature.path[i]);
                hasher.update(&tmp);
            } else {
                // Tc = H(I || u32str(node_num/2) || u16str(D_INTR) || tmp || path[i])
                hasher.update(&tmp);
                hasher.update(&signature.path[i]);
            }
            hasher.finalize_into(&mut tmp);
            node_num /= 2;
        }
        if self.k == tmp {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

/// Converts a [PublicKey] into its byte representation
impl<Mode: LmsMode> From<PublicKey<Mode>>
    for GenericArray<u8, Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>>
where
    <Mode::Hasher as OutputSizeUser>::OutputSize: Add<U24>,
    Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>: ArrayLength<u8>,
{
    fn from(pk: PublicKey<Mode>) -> Self {
        // Return u32(type) || u32(otstype) || id || k
        GenericArray::from_exact_iter(
            std::iter::empty()
                .chain(Mode::TYPECODE.to_be_bytes())
                .chain(Mode::OtsMode::TYPECODE.to_be_bytes())
                .chain(pk.id)
                .chain(pk.k),
        )
        .unwrap()
    }
}

/// Tries to parse a [PublicKey] from an exact slice
impl<'a, Mode: LmsMode> TryFrom<&'a [u8]> for PublicKey<Mode> {
    type Error = LmsDeserializeError;

    fn try_from(pk: &'a [u8]) -> Result<Self, Self::Error> {
        let expected_len = Mode::M + ID_LEN + 8;

        match pk.len().cmp(&expected_len) {
            Ordering::Less => return Err(LmsDeserializeError::TooShort),
            Ordering::Greater => return Err(LmsDeserializeError::TooLong),
            Ordering::Equal => (),
        };

        let (alg, pk) = pk.split_at(4);

        // will never panic because we already checked the length
        if u32::from_be_bytes(alg.try_into().unwrap()) != Mode::TYPECODE {
            return Err(LmsDeserializeError::WrongAlgorithm);
        }

        // pk is now guaranteed to be of the form u32(otstype) || ID || K
        let (otstype, id_k) = pk.split_at(4);

        // Check that otstype is correct
        if u32::from_be_bytes(otstype.try_into().unwrap()) != Mode::OtsMode::TYPECODE {
            return Err(LmsDeserializeError::WrongAlgorithm);
        }

        let (id, k) = id_k.split_at(ID_LEN);

        Ok(Self {
            id: id.try_into().unwrap(),
            k: GenericArray::clone_from_slice(k),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;

    use crate::{
        lms::modes::*,
        lms::PrivateKey,
        lms::PublicKey,
        ots::{LmsOtsSha256N32W4, LmsOtsSha256N32W8},
    };
    use digest::OutputSizeUser;
    use generic_array::{ArrayLength, GenericArray};
    use hex_literal::hex;
    use typenum::{Sum, U24};

    const KAT1: [u8; 56] = hex!(
        "
        00000005
        00000004
        61a5d57d37f5e46bfb7520806b07a1b8
        50650e3b31fe4a773ea29a07f09cf2ea
        30e579f0df58ef8e298da0434cb2b878"
    );

    #[test]
    fn test_pubkey_deserialize_kat1() {
        let pk = PublicKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(&KAT1[..]).unwrap();
        let expected = PublicKey::<LmsSha256M32H5<LmsOtsSha256N32W8>> {
            id: hex!("61a5d57d37f5e46bfb7520806b07a1b8"),
            k: hex!("50650e3b31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878").into(),
        };
        assert_eq!(pk, expected);
    }

    #[test]
    fn test_pubkey_deserialize_kat1_wrong_lms_mode() {
        let pk = PublicKey::<LmsSha256M32H10<LmsOtsSha256N32W8>>::try_from(&KAT1[..]);
        assert_eq!(pk, Err(crate::error::LmsDeserializeError::WrongAlgorithm));
    }

    #[test]
    fn test_pubkey_deserialize_kat1_wrong_otsmode() {
        let pk = PublicKey::<LmsSha256M32H5<LmsOtsSha256N32W4>>::try_from(&KAT1[..]);
        assert_eq!(pk, Err(crate::error::LmsDeserializeError::WrongAlgorithm));
    }

    #[test]
    fn test_pubkey_deserialize_kat1_too_short() {
        let pk_bytes = &KAT1[..(KAT1.len() - 4)];
        let pk = PublicKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(pk_bytes);
        assert_eq!(pk, Err(crate::error::LmsDeserializeError::TooShort));
    }

    #[test]
    fn test_pubkey_deserialize_kat1_too_long() {
        let mut pk_bytes = vec![42; 4];
        pk_bytes.extend_from_slice(&KAT1[..]);

        let pk = PublicKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(&pk_bytes[..]);
        assert_eq!(pk, Err(crate::error::LmsDeserializeError::TooLong));
    }

    #[test]
    fn test_kat1_round_trip() {
        let pk_bytes = hex!(
            "
            00000005
            00000004
            61a5d57d37f5e46bfb7520806b07a1b8
            50650e3b31fe4a773ea29a07f09cf2ea
            30e579f0df58ef8e298da0434cb2b878"
        );
        let pk = PublicKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(&pk_bytes[..]).unwrap();
        let pk_serialized: GenericArray<u8, _> = pk.clone().into();
        let bytes = pk_serialized.as_slice();
        assert_eq!(bytes, &pk_bytes[..]);
    }

    #[test]
    fn test_kat2() {
        // Tests that the serialized public key from RFC seed matches the expected value
        let seed = hex!("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
        let id = hex!("215f83b7ccb9acbcd08db97b0d04dc2b");
        let expected_pubkey = hex!(
            "
            00000005
            00000004
            215f83b7ccb9acbcd08db97b0d04dc2b
            a1cd035833e0e90059603f26e07ad2aa
            d152338e7a5e5984bcd5f7bb4eba40b7
        "
        );
        let lms_priv = PrivateKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::new_from_seed(id, seed);
        let lms_pub = lms_priv.public();
        let lms_pub_serialized: GenericArray<u8, _> = lms_pub.into();
        let bytes = lms_pub_serialized.as_slice();
        assert_eq!(bytes, &expected_pubkey[..]);
    }

    fn test_serialize_deserialize_random<Mode: LmsMode>()
    where
        PublicKey<Mode>: std::fmt::Debug,
        <Mode::Hasher as OutputSizeUser>::OutputSize: Add<U24>,
        Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>: ArrayLength<u8>,
    {
        let rng = rand::thread_rng();
        let lms_priv = PrivateKey::<Mode>::new(rng);
        let lms_pub = lms_priv.public();
        let lms_pub_serialized: GenericArray<
            u8,
            Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>,
        > = lms_pub.clone().into();
        let bytes = lms_pub_serialized.as_slice();
        let lms_pub_deserialized = PublicKey::<Mode>::try_from(bytes).unwrap();
        assert_eq!(lms_pub, lms_pub_deserialized);
    }

    #[test]
    fn test_serialize_deserialize_random_lms_sha256_m32_h5_lms_ots_sha256_n32_w8() {
        test_serialize_deserialize_random::<LmsSha256M32H5<LmsOtsSha256N32W8>>();
    }

    #[test]
    fn test_serialize_deserialize_random_lms_sha256_m32_h10_lms_ots_sha256_n32_w8() {
        test_serialize_deserialize_random::<LmsSha256M32H10<LmsOtsSha256N32W8>>();
    }

    // These tests use too much memory and overflow the stack
    /*
    #[test]
    fn test_serialize_deserialize_random_lms_sha256_m32_h15_lms_ots_sha256_n32_w8(){
        test_serialize_deserialize_random::<LmsSha256M32H15<LmsOtsSha256N32W8>>();
    }

    #[test]
    fn test_serialize_deserialize_random_lms_sha256_m32_h20_lms_ots_sha256_n32_w8(){
        test_serialize_deserialize_random::<LmsSha256M32H20<LmsOtsSha256N32W8>>();
    }

    #[test]
    fn test_serialize_deserialize_random_lms_sha256_m32_h25_lms_ots_sha256_n32_w8(){
        test_serialize_deserialize_random::<LmsSha256M32H25<LmsOtsSha256N32W8>>();
    }
    */
}
