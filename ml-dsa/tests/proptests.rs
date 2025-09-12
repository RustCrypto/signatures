use hybrid_array::AsArrayRef;
use ml_dsa::{
    KeyGen, KeyPair, MlDsa44, MlDsa65, MlDsa87, Signature,
    signature::{Signer, Verifier},
};
use proptest::prelude::*;

/// Example message
const MSG: &[u8] = b"Hello world";

// Keypairs
prop_compose! {
    fn mldsa44_keypair()(seed_bytes in any::<[u8; 32]>()) -> KeyPair<MlDsa44> {
       MlDsa44::from_seed(seed_bytes.as_array_ref())
    }
}
prop_compose! {
    fn mldsa65_keypair()(seed_bytes in any::<[u8; 32]>()) -> KeyPair<MlDsa65> {
       MlDsa65::from_seed(seed_bytes.as_array_ref())
    }
}
prop_compose! {
    fn mldsa87_keypair()(seed_bytes in any::<[u8; 32]>()) -> KeyPair<MlDsa87> {
        MlDsa87::from_seed(seed_bytes.as_array_ref())
    }
}

macro_rules! round_trip_test {
    ($params:path, $keypair:expr) => {
        let sig = $keypair.signing_key().sign(MSG);

        // Check signature verification
        let verify_result = $keypair.verifying_key().verify(MSG, &sig);
        prop_assert!(verify_result.is_ok());

        // Check signature encoding round trip
        let sig_decoded = Signature::<$params>::decode(&sig.encode());
        prop_assert_eq!(Some(sig), sig_decoded);
    };
}

proptest! {
    #[test]
    fn mldsa44_round_trip(keypair in mldsa44_keypair()) {
        round_trip_test!(MlDsa44, keypair);
    }

    #[test]
    fn mldsa65_round_trip(keypair in mldsa65_keypair()) {
        round_trip_test!(MlDsa65, keypair);
    }

    #[test]
    fn mldsa87_round_trip(keypair in mldsa87_keypair()) {
        round_trip_test!(MlDsa87, keypair);
    }
}
