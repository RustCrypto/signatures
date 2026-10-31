//! PKCS#8 tests (i.e. private key serialization)

#![cfg(all(feature = "pkcs8", feature = "alloc"))]

use core::ops::Deref;
use ml_dsa::{
    ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey, VerifyingKey,
    signature::Keypair,
};
use pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, PrivateKeyInfoRef,
    der::{AnyRef, Encode, pem::LineEnding},
    spki::{self, AssociatedAlgorithmIdentifier, SubjectPublicKeyInfoRef},
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
        assert!(sk == *ssk.expanded_key());
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

#[test]
fn algorithm_identifier_parameters_rejected() {
    fn check<P>()
    where
        P: MlDsaParams,
        P: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
    {
        let sk = SigningKey::<P>::from_seed(&Seed::from([0x42; 32]));

        let sk_der = sk.to_pkcs8_der().expect("serialize private key");
        let mut private_key_info =
            PrivateKeyInfoRef::try_from(sk_der.as_bytes()).expect("parse private key");
        private_key_info.algorithm.parameters = Some(AnyRef::NULL);
        let der = private_key_info.to_der().expect("serialize private key");
        assert_eq!(
            SigningKey::<P>::from_pkcs8_der(&der).err(),
            Some(pkcs8::Error::ParametersMalformed)
        );
        assert_eq!(
            ExpandedSigningKey::<P>::from_pkcs8_der(&der).err(),
            Some(pkcs8::Error::ParametersMalformed)
        );

        let pk_der = sk
            .verifying_key()
            .to_public_key_der()
            .expect("serialize public key");
        let mut spki =
            SubjectPublicKeyInfoRef::try_from(pk_der.as_bytes()).expect("parse public key");
        spki.algorithm.parameters = Some(AnyRef::NULL);
        let der = spki.to_der().expect("serialize public key");
        assert_eq!(
            VerifyingKey::<P>::from_public_key_der(&der).err(),
            Some(spki::Error::KeyMalformed)
        );
    }

    check::<MlDsa44>();
    check::<MlDsa65>();
    check::<MlDsa87>();
}
