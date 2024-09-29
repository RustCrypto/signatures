use std::cmp::Ordering;
use std::ops::Add;

use crate::constants::{D_LEAF, ID_LEN};

use crate::error::LmsDeserializeError;
use crate::lms::Signature;
use crate::types::Typecode;
use crate::{constants::D_INTR, lms::LmsMode};
use digest::{Digest, OutputSizeUser};
use hybrid_array::{Array, ArraySize};
use signature::{Error, Verifier};
use typenum::{Sum, U24};

//use crate::signature::Signature as Signature;
use crate::types::Identifier;

use digest::Output;

#[derive(Debug)]
/// Opaque struct representing a LMS public key
pub struct VerifyingKey<Mode: LmsMode> {
    pub(crate) id: Identifier,
    pub(crate) k: Output<Mode::Hasher>,
}

impl<Mode: LmsMode> Clone for VerifyingKey<Mode> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            k: self.k.clone(),
        }
    }
}

impl<Mode: LmsMode> PartialEq for VerifyingKey<Mode> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.k == other.k
    }
}

impl<Mode: LmsMode> VerifyingKey<Mode> {
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

impl<Mode: LmsMode> Verifier<Signature<Mode>> for VerifyingKey<Mode> {
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

/// Converts a [`VerifyingKey`] into its byte representation
impl<Mode: LmsMode> From<VerifyingKey<Mode>>
    for Array<u8, Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>>
where
    <Mode::Hasher as OutputSizeUser>::OutputSize: Add<U24>,
    Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>: ArraySize,
{
    fn from(pk: VerifyingKey<Mode>) -> Self {
        // Return u32(type) || u32(otstype) || id || k
        Array::try_from_iter(
            std::iter::empty()
                .chain(Mode::TYPECODE.to_be_bytes())
                .chain(Mode::OtsMode::TYPECODE.to_be_bytes())
                .chain(pk.id)
                .chain(pk.k),
        )
        .unwrap()
    }
}

/// Tries to parse a [`VerifyingKey`] from an exact slice
impl<'a, Mode: LmsMode> TryFrom<&'a [u8]> for VerifyingKey<Mode> {
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
            k: Array::try_from(k).expect("size invariant violation"),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;

    use crate::{
        lms::modes::*,
        lms::SigningKey,
        lms::VerifyingKey,
        ots::{LmsOtsSha256N32W4, LmsOtsSha256N32W8},
    };
    use digest::OutputSizeUser;
    use hex_literal::hex;
    use hybrid_array::{Array, ArraySize};
    use typenum::{Sum, U24};

    // RFC 8554 Appendix F. Test Case 1
    // Top-level LMS Public Key
    // LM_SHA256_M32_H5 / LMOTS_SHA256_N32_W8
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
        let pk = VerifyingKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(&KAT1[..]).unwrap();
        let expected = VerifyingKey::<LmsSha256M32H5<LmsOtsSha256N32W8>> {
            id: hex!("61a5d57d37f5e46bfb7520806b07a1b8"),
            k: hex!("50650e3b31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878").into(),
        };
        assert_eq!(pk, expected);
    }

    #[test]
    fn test_pubkey_deserialize_kat1_wrong_lms_mode() {
        let pk = VerifyingKey::<LmsSha256M32H10<LmsOtsSha256N32W8>>::try_from(&KAT1[..]);
        assert_eq!(pk, Err(crate::error::LmsDeserializeError::WrongAlgorithm));
    }

    #[test]
    fn test_pubkey_deserialize_kat1_wrong_otsmode() {
        let pk = VerifyingKey::<LmsSha256M32H5<LmsOtsSha256N32W4>>::try_from(&KAT1[..]);
        assert_eq!(pk, Err(crate::error::LmsDeserializeError::WrongAlgorithm));
    }

    #[test]
    fn test_pubkey_deserialize_kat1_too_short() {
        let pk_bytes = &KAT1[..(KAT1.len() - 4)];
        let pk = VerifyingKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(pk_bytes);
        assert_eq!(pk, Err(crate::error::LmsDeserializeError::TooShort));
    }

    #[test]
    fn test_pubkey_deserialize_kat1_too_long() {
        let mut pk_bytes = vec![42; 4];
        pk_bytes.extend_from_slice(&KAT1[..]);

        let pk = VerifyingKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(&pk_bytes[..]);
        assert_eq!(pk, Err(crate::error::LmsDeserializeError::TooLong));
    }

    #[test]
    fn test_kat1_round_trip() {
        let pk = VerifyingKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(&KAT1[..]).unwrap();
        let pk_serialized: Array<u8, _> = pk.clone().into();
        let bytes = pk_serialized.as_slice();
        assert_eq!(bytes, &KAT1[..]);
    }

    // RFC 8554 Appendix F. Test Case 2
    // Top-level LMS Public Key
    // LM_SHA256_M32_H10 / LMOTS_SHA256_N32_W4
    #[test]
    fn test_kat2() {
        // Tests that the serialized public key from RFC seed matches the expected value
        let seed = hex!("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        let id = hex!("d08fabd4a2091ff0a8cb4ed834e74534");
        let expected_pubkey = hex!(
            "
            00000006
            00000003
            d08fabd4a2091ff0a8cb4ed834e74534
            32a58885cd9ba0431235466bff9651c6
            c92124404d45fa53cf161c28f1ad5a8e
        "
        );
        let lms_priv =
            SigningKey::<LmsSha256M32H10<LmsOtsSha256N32W4>>::new_from_seed(id, seed).unwrap();
        let lms_pub = lms_priv.public();
        let lms_pub_serialized: Array<u8, _> = lms_pub.into();
        let bytes = lms_pub_serialized.as_slice();
        assert_eq!(bytes, &expected_pubkey[..]);
    }

    fn test_serialize_deserialize_random<Mode: LmsMode>()
    where
        VerifyingKey<Mode>: std::fmt::Debug,
        <Mode::Hasher as OutputSizeUser>::OutputSize: Add<U24>,
        Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>: ArraySize,
    {
        let rng = rand::thread_rng();
        let lms_priv = SigningKey::<Mode>::new(rng);
        let lms_pub = lms_priv.public();
        let lms_pub_serialized: Array<u8, Sum<<Mode::Hasher as OutputSizeUser>::OutputSize, U24>> =
            lms_pub.clone().into();
        let bytes = lms_pub_serialized.as_slice();
        let lms_pub_deserialized = VerifyingKey::<Mode>::try_from(bytes).unwrap();
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
