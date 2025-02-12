use ml_dsa::{signature::Signer, KeyGen, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, B32};
use proptest::prelude::*;

fn example_signature<P: MlDsaParams>(seed_bytes: &B32) -> Signature<P> {
    let keypair = P::key_gen_internal(seed_bytes);
    let msg = b"";
    keypair.signing_key().sign(msg)
}

prop_compose! {
    fn mldsa44_signature()(seed_bytes in any::<[u8; 32]>()) -> Signature<MlDsa44> {
        example_signature::<MlDsa44>(seed_bytes.as_ref())
    }
}

prop_compose! {
    fn mldsa65_signature()(seed_bytes in any::<[u8; 32]>()) -> Signature<MlDsa65> {
        example_signature::<MlDsa65>(seed_bytes.as_ref())
    }
}

prop_compose! {
    fn mldsa87_signature()(seed_bytes in any::<[u8; 32]>()) -> Signature<MlDsa87> {
        example_signature::<MlDsa87>(seed_bytes.as_ref())
    }
}

proptest! {
    #[test]
    fn mldsa44_round_trip(sig in mldsa44_signature()) {
        let sig_decoded = Signature::<MlDsa44>::decode(&sig.encode());
        prop_assert_eq!(Some(sig), sig_decoded);
    }

    #[test]
    fn mldsa65_round_trip(sig in mldsa65_signature()) {
        let sig_decoded = Signature::<MlDsa65>::decode(&sig.encode());
        prop_assert_eq!(Some(sig), sig_decoded);
    }

    #[test]
    fn mldsa87_round_trip(sig in mldsa87_signature()) {
        let sig_decoded = Signature::<MlDsa87>::decode(&sig.encode());
        prop_assert_eq!(Some(sig), sig_decoded);
    }
}
