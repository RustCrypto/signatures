//! Cached verification keys retain their value and behavior across key lifetimes.

#![allow(clippy::unwrap_used, reason = "tests")]

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey, VerifyingKey};
use signature::Keypair;

fn check<P: MlDsaParams>() {
    for fill in [0, 1, 0x7f, 0xff] {
        let seed = Seed::from([fill; 32]);
        let signing_key = SigningKey::<P>::from_seed(&seed);
        let verifying_key = signing_key.verifying_key();
        let derived = signing_key.expanded_key().verifying_key();
        let decoded = VerifyingKey::decode(&verifying_key.encode());
        assert!(verifying_key == derived);
        assert!(verifying_key == decoded);

        let cloned = signing_key.clone();
        drop(signing_key);
        assert!(cloned.verifying_key() == verifying_key);
        assert_eq!(cloned.to_seed(), seed);

        for (message, context) in [(&[][..], &[][..]), (&[0x42; 1024][..], &[0x24; 255][..])] {
            let signature = cloned
                .expanded_key()
                .sign_deterministic(message, context)
                .unwrap();
            assert!(verifying_key.verify_with_context(message, context, &signature));
            assert!(derived.verify_with_context(message, context, &signature));
            assert!(decoded.verify_with_context(message, context, &signature));
            assert!(!verifying_key.verify_with_context(b"wrong message", context, &signature));
            assert!(!verifying_key.verify_with_context(message, b"wrong context", &signature));
        }
    }
}

#[test]
fn key_cache_44() {
    check::<MlDsa44>();
}

#[test]
fn key_cache_65() {
    check::<MlDsa65>();
}

#[test]
fn key_cache_87() {
    check::<MlDsa87>();
}
