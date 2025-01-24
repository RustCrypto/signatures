#![cfg(all(feature = "pkcs8", feature = "alloc"))]

use core::ops::Deref;
use ml_dsa::{KeyPair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, SigningKey, VerifyingKey};
use pkcs8::{
    der::{pem::LineEnding, AnyRef},
    spki::AssociatedAlgorithmIdentifier,
    DecodePrivateKey, DecodePublicKey, EncodePublicKey,
};
use signature::Keypair;

#[test]
fn private_key_serialization() {
    fn test_roundtrip<P>(private_bytes: &str, public_bytes: &str)
    where
        P: MlDsaParams,
        P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
    {
        let sk = SigningKey::<P>::from_pkcs8_pem(private_bytes).expect("parse private key");
        let kp = KeyPair::<P>::from_pkcs8_pem(private_bytes).expect("parse private key");
        assert!(sk == kp.signing_key);

        let pk = VerifyingKey::<P>::from_public_key_pem(public_bytes).expect("parse public key");
        assert_eq!(
            pk.to_public_key_pem(LineEnding::LF)
                .expect("serialize public key")
                .deref(),
            public_bytes
        );

        assert_eq!(kp.verifying_key(), pk);
    }

    test_roundtrip::<MlDsa44>(
        include_str!("examples/ML-DSA-44.priv"),
        include_str!("examples/ML-DSA-44.pub"),
    );
    test_roundtrip::<MlDsa65>(
        include_str!("examples/ML-DSA-65.priv"),
        include_str!("examples/ML-DSA-65.pub"),
    );
    test_roundtrip::<MlDsa87>(
        include_str!("examples/ML-DSA-87.priv"),
        include_str!("examples/ML-DSA-87.pub"),
    );
}
