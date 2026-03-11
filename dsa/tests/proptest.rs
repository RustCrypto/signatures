//! Property-based tests.

#![cfg(all(feature = "hazmat", feature = "pkcs8"))]

use chacha20::{ChaCha8Rng, rand_core::SeedableRng};
use der::{Decode, Encode, Sequence, asn1::Uint};
use dsa::{Components, KeySize, Signature, SigningKey, VerifyingKey, signature::Verifier};
use pkcs8::DecodePublicKey;
use proptest::prelude::*;

#[derive(Sequence)]
struct MockSignature {
    r: Uint,
    s: Uint,
}

const OPENSSL_PEM_PUBLIC_KEY: &str = include_str!("pems/public.pem");

prop_compose! {
    fn private_key()(seed in any::<[u8; 32]>()) -> SigningKey {
        let mut rng = ChaCha8Rng::from_seed(seed);
        #[allow(deprecated)]
        let components = Components::generate(&mut rng, KeySize::DSA_1024_160);
        SigningKey::generate(&mut rng, components)
    }
}

proptest! {
    #[test]
    fn dsa_signature_verification( r in any::<Vec<u8>>(), s in any::<Vec<u8>>(),) {
        let verifying_key = VerifyingKey::from_public_key_pem(OPENSSL_PEM_PUBLIC_KEY)
            .expect("Failed to decode PEM encoded OpenSSL public key");

        let asn1 = MockSignature {
            r: Uint::new(&r).unwrap(),
            s: Uint::new(&s).unwrap(),
        }
        .to_der()
        .expect("Failed to serialize signature");

        let Ok(signature) = Signature::from_der(&asn1) else {
            return Ok(());
        };

        prop_assert!(verifying_key.verify(&[], &signature).is_err());
    }
}
