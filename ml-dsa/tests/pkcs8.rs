#![cfg(all(feature = "pkcs8", feature = "alloc"))]

use core::ops::Deref;
use ml_dsa::{
    ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, SigningKey, VerifyingKey,
    signature::Keypair,
};
use pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
    der::{AnyRef, pem::LineEnding},
    spki::AssociatedAlgorithmIdentifier,
};

#[test]
fn private_key_serialization() {
    fn test_roundtrip<P>(private_bytes: &str, public_bytes: &str)
    where
        P: MlDsaParams,
        P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
    {
        let sk = ExpandedSigningKey::<P>::from_pkcs8_pem(private_bytes).expect("parse private key");
        let ssk = SigningKey::<P>::from_pkcs8_pem(private_bytes).expect("parse private key");
        assert!(sk == *ssk.signing_key());
        assert_eq!(
            ssk.to_pkcs8_pem(LineEnding::LF)
                .expect("serialize private seed")
                .deref(),
            private_bytes
        );

        let pk = VerifyingKey::<P>::from_public_key_pem(public_bytes).expect("parse public key");
        assert_eq!(
            pk.to_public_key_pem(LineEnding::LF)
                .expect("serialize public key")
                .deref(),
            public_bytes
        );

        assert_eq!(sk.verifying_key(), pk);
        assert_eq!(ssk.verifying_key(), pk);
    }

    test_roundtrip::<MlDsa44>(
        include_str!("examples/ML-DSA-44-seed.priv"),
        include_str!("examples/ML-DSA-44.pub"),
    );
    test_roundtrip::<MlDsa65>(
        include_str!("examples/ML-DSA-65-seed.priv"),
        include_str!("examples/ML-DSA-65.pub"),
    );
    test_roundtrip::<MlDsa87>(
        include_str!("examples/ML-DSA-87-seed.priv"),
        include_str!("examples/ML-DSA-87.pub"),
    );
}
