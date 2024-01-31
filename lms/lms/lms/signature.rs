//! Contains the [Signature] type

use crate::error::LmsDeserializeError;
use crate::lms::LmsMode;
use crate::ots::modes::LmsOtsMode;
use crate::ots::Signature as OtsSignature;
use generic_array::{ArrayLength, GenericArray};
use signature::SignatureEncoding;

use std::{
    cmp::Ordering,
    ops::{Add, Mul},
};

use typenum::{Prod, Sum, U1, U4};

/// Opaque struct representing a LMS signature
pub struct Signature<Mode: LmsMode> {
    pub(crate) q: u32, // TODO: do these really need to be public?
    pub(crate) lmots_sig: OtsSignature<Mode::OtsMode>,
    pub(crate) path: GenericArray<digest::Output<Mode::Hasher>, Mode::HLen>,
}

// manual implementation is required to not require bounds on Mode
impl<Mode: LmsMode> Clone for Signature<Mode> {
    fn clone(&self) -> Self {
        Self {
            q: self.q,
            lmots_sig: self.lmots_sig.clone(),
            path: self.path.clone(),
        }
    }
}

// manual implementation is required to not require bounds on Mode
impl<Mode: LmsMode> PartialEq for Signature<Mode> {
    fn eq(&self, other: &Self) -> bool {
        self.q == other.q && self.lmots_sig == other.lmots_sig && self.path == other.path
    }
}

impl<Mode: LmsMode> SignatureEncoding for Signature<Mode>
where
    <Mode::OtsMode as LmsOtsMode>::PLen: Add<U1>,
    <Mode::OtsMode as LmsOtsMode>::NLen: Mul<Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>,
    Prod<<Mode::OtsMode as LmsOtsMode>::NLen, Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>:
        Add<U4>,
    Sum<
        Prod<<Mode::OtsMode as LmsOtsMode>::NLen, Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>,
        U4,
    >: ArrayLength<u8>,
{
    type Repr = Vec<u8>; // TODO: GenericArray
}

impl<Mode: LmsMode> From<Signature<Mode>> for Vec<u8>
where
    <Mode::OtsMode as LmsOtsMode>::PLen: Add<U1>,
    <Mode::OtsMode as LmsOtsMode>::NLen: Mul<Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>,
    Prod<<Mode::OtsMode as LmsOtsMode>::NLen, Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>:
        Add<U4>,
    Sum<
        Prod<<Mode::OtsMode as LmsOtsMode>::NLen, Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>,
        U4,
    >: ArrayLength<u8>,
{
    fn from(val: Signature<Mode>) -> Self {
        let mut sig = Vec::new();
        sig.extend_from_slice(&val.q.to_be_bytes());
        let lms_sig: GenericArray<u8, _> = val.lmots_sig.into();
        sig.extend_from_slice(&lms_sig);
        sig.extend_from_slice(&Mode::TYPECODE.to_be_bytes());
        for node in val.path {
            sig.extend_from_slice(&node);
        }
        sig
    }
}

/// Tries to parse a [Signature] from an exact slice
impl<Mode: LmsMode> TryFrom<&[u8]> for Signature<Mode> {
    type Error = LmsDeserializeError;

    fn try_from(sig: &[u8]) -> Result<Self, Self::Error> {
        // Follows the validations in algorithm 6a of RFC 8554

        // Fully check signature length up-front. Removes need for checks as we go.
        match sig
            .len()
            .cmp(&(8 + Mode::OtsMode::SIG_LEN + Mode::M * Mode::H))
        {
            Ordering::Less => return Err(LmsDeserializeError::TooShort),
            Ordering::Greater => return Err(LmsDeserializeError::TooLong),
            Ordering::Equal => (),
        };

        // 6a.2.a: Get q
        let (q_bytes, sig) = sig.split_at(4);
        let q = u32::from_be_bytes(q_bytes.try_into().unwrap());

        // 6a.2.i: If q >= 2^H, return INVALID.
        if q >= 1 << Mode::H {
            return Err(LmsDeserializeError::InvalidQ);
        }

        // We already checked that this won't panic
        let (lmots_sig, sig) = sig.split_at(Mode::OtsMode::SIG_LEN);

        // Checks that the OTS mode is correct happen inside `try_from`
        let ots_signature = OtsSignature::<Mode::OtsMode>::try_from(lmots_sig)?;

        // 6a.2.f: Get LMS typecode (sigtype)
        let (sigtype, path) = sig.split_at(4);

        // 6a.2.g: If the OTS typecode is not equal to the typecode of the
        //         expected LM-OTS Mode, return INVALID.
        if u32::from_be_bytes(sigtype.try_into().unwrap()) != Mode::TYPECODE {
            return Err(LmsDeserializeError::WrongAlgorithm);
        }

        // Path length is already validated by initial length check
        let path = path
            .chunks_exact(Mode::M)
            .map(GenericArray::clone_from_slice)
            .collect();

        Ok(Self {
            q,
            lmots_sig: ots_signature,
            path,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::{Add, Mul};

    use crate::lms::modes::*;
    use crate::lms::{PrivateKey, PublicKey, Signature};
    use crate::ots::modes::*;
    use generic_array::ArrayLength;
    use hex_literal::hex;
    use rand::thread_rng;
    use signature::{RandomizedSignerMut, Verifier};
    use typenum::{Prod, Sum, U1, U4};

    #[test]
    fn test_deserialize_kat1() {
        let pk_bytes = hex!("0000000500000004d2f14ff6346af964569f7d6cb880a1b66c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab");
        let sig_bytes = hex!(
            "
            0000000a
            00000004
            0703c491e7558b35011ece3592eaa5da
            4d918786771233e8353bc4f62323185c
            95cae05b899e35dffd71705470620998
            8ebfdf6e37960bb5c38d7657e8bffeef
            9bc042da4b4525650485c66d0ce19b31
            7587c6ba4bffcc428e25d08931e72dfb
            6a120c5612344258b85efdb7db1db9e1
            865a73caf96557eb39ed3e3f426933ac
            9eeddb03a1d2374af7bf771855774562
            37f9de2d60113c23f846df26fa942008
            a698994c0827d90e86d43e0df7f4bfcd
            b09b86a373b98288b7094ad81a0185ac
            100e4f2c5fc38c003c1ab6fea479eb2f
            5ebe48f584d7159b8ada03586e65ad9c
            969f6aecbfe44cf356888a7b15a3ff07
            4f771760b26f9c04884ee1faa329fbf4
            e61af23aee7fa5d4d9a5dfcf43c4c26c
            e8aea2ce8a2990d7ba7b57108b47dabf
            beadb2b25b3cacc1ac0cef346cbb90fb
            044beee4fac2603a442bdf7e507243b7
            319c9944b1586e899d431c7f91bcccc8
            690dbf59b28386b2315f3d36ef2eaa3c
            f30b2b51f48b71b003dfb08249484201
            043f65f5a3ef6bbd61ddfee81aca9ce6
            0081262a00000480dcbc9a3da6fbef5c
            1c0a55e48a0e729f9184fcb1407c3152
            9db268f6fe50032a363c9801306837fa
            fabdf957fd97eafc80dbd165e435d0e2
            dfd836a28b354023924b6fb7e48bc0b3
            ed95eea64c2d402f4d734c8dc26f3ac5
            91825daef01eae3c38e3328d00a77dc6
            57034f287ccb0f0e1c9a7cbdc828f627
            205e4737b84b58376551d44c12c3c215
            c812a0970789c83de51d6ad787271963
            327f0a5fbb6b5907dec02c9a90934af5
            a1c63b72c82653605d1dcce51596b3c2
            b45696689f2eb382007497557692caac
            4d57b5de9f5569bc2ad0137fd47fb47e
            664fcb6db4971f5b3e07aceda9ac130e
            9f38182de994cff192ec0e82fd6d4cb7
            f3fe00812589b7a7ce51544045643301
            6b84a59bec6619a1c6c0b37dd1450ed4
            f2d8b584410ceda8025f5d2d8dd0d217
            6fc1cf2cc06fa8c82bed4d944e71339e
            ce780fd025bd41ec34ebff9d4270a322
            4e019fcb444474d482fd2dbe75efb203
            89cc10cd600abb54c47ede93e08c114e
            db04117d714dc1d525e11bed8756192f
            929d15462b939ff3f52f2252da2ed64d
            8fae88818b1efa2c7b08c8794fb1b214
            aa233db3162833141ea4383f1a6f120b
            e1db82ce3630b3429114463157a64e91
            234d475e2f79cbf05e4db6a9407d72c6
            bff7d1198b5c4d6aad2831db61274993
            715a0182c7dc8089e32c8531deed4f74
            31c07c02195eba2ef91efb5613c37af7
            ae0c066babc69369700e1dd26eddc0d2
            16c781d56e4ce47e3303fa73007ff7b9
            49ef23be2aa4dbf25206fe45c20dd888
            395b2526391a724996a44156beac8082
            12858792bf8e74cba49dee5e8812e019
            da87454bff9e847ed83db07af3137430
            82f880a278f682c2bd0ad6887cb59f65
            2e155987d61bbf6a88d36ee93b6072e6
            656d9ccbaae3d655852e38deb3a2dcf8
            058dc9fb6f2ab3d3b3539eb77b248a66
            1091d05eb6e2f297774fe6053598457c
            c61908318de4b826f0fc86d4bb117d33
            e865aa805009cc2918d9c2f840c4da43
            a703ad9f5b5806163d7161696b5a0adc
            00000005
            d5c0d1bebb06048ed6fe2ef2c6cef305
            b3ed633941ebc8b3bec9738754cddd60
            e1920ada52f43d055b5031cee6192520
            d6a5115514851ce7fd448d4a39fae2ab
            2335b525f484e9b40d6a4a969394843b
            dcf6d14c48e8015e08ab92662c05c6e9
            f90b65a7a6201689999f32bfd368e5e3
            ec9cb70ac7b8399003f175c40885081a
            09ab3034911fe125631051df0408b394
            6b0bde790911e8978ba07dd56c73e7ee
        "
        );
        let msg = hex!(
            "
        54686520706f77657273206e6f742064
        656c65676174656420746f2074686520
        556e6974656420537461746573206279
        2074686520436f6e737469747574696f
        6e2c206e6f722070726f686962697465
        6420627920697420746f207468652053
        74617465732c20617265207265736572
        76656420746f20746865205374617465
        7320726573706563746976656c792c20
        6f7220746f207468652070656f706c65
        2e0a"
        );
        let pk = PublicKey::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(&pk_bytes[..]).unwrap();
        let sig = Signature::<LmsSha256M32H5<LmsOtsSha256N32W8>>::try_from(&sig_bytes[..]).unwrap();
        assert!(pk.verify(&msg[..], &sig).is_ok());
    }

    fn test_serialize_deserialize_random<Mode: LmsMode>()
    where
        <Mode::OtsMode as LmsOtsMode>::PLen: Add<U1>,
        <Mode::OtsMode as LmsOtsMode>::NLen: Mul<Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>,
        Prod<<Mode::OtsMode as LmsOtsMode>::NLen, Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>:
            Add<U4>,
        Sum<
            Prod<<Mode::OtsMode as LmsOtsMode>::NLen, Sum<<Mode::OtsMode as LmsOtsMode>::PLen, U1>>,
            U4,
        >: ArrayLength<u8>,
    {
        let mut rng = thread_rng();
        let mut sk = PrivateKey::<Mode>::new(&mut rng);
        let pk = sk.public();
        let msg = b"Hello, world!";
        let sig = sk.sign_with_rng(&mut rng, msg);
        let sig_bytes: Vec<_> = sig.clone().into();
        let sig2 = Signature::<Mode>::try_from(&sig_bytes[..]).unwrap();
        assert!(pk.verify(msg, &sig2).is_ok());
    }

    #[test]
    fn test_serialize_deserialize_random_h5_w1() {
        test_serialize_deserialize_random::<LmsSha256M32H5<LmsOtsSha256N32W1>>();
    }

    #[test]
    fn test_serialize_deserialize_random_h5_w2() {
        test_serialize_deserialize_random::<LmsSha256M32H5<LmsOtsSha256N32W2>>();
    }

    #[test]
    fn test_serialize_deserialize_random_h5_w4() {
        test_serialize_deserialize_random::<LmsSha256M32H5<LmsOtsSha256N32W4>>();
    }

    #[test]
    fn test_serialize_deserialize_random_h5_w8() {
        test_serialize_deserialize_random::<LmsSha256M32H5<LmsOtsSha256N32W8>>();
    }

    #[test]
    fn test_serialize_deserialize_random_h10_w1() {
        test_serialize_deserialize_random::<LmsSha256M32H10<LmsOtsSha256N32W1>>();
    }

    #[test]
    fn test_serialize_deserialize_random_h10_w2() {
        test_serialize_deserialize_random::<LmsSha256M32H10<LmsOtsSha256N32W2>>();
    }

    #[test]
    fn test_serialize_deserialize_random_h10_w4() {
        test_serialize_deserialize_random::<LmsSha256M32H10<LmsOtsSha256N32W4>>();
    }

    #[test]
    fn test_serialize_deserialize_random_h10_w8() {
        test_serialize_deserialize_random::<LmsSha256M32H10<LmsOtsSha256N32W8>>();
    }
}
