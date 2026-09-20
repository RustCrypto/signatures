//! Regressions for stack usage with heap offload enabled.
//!
//! Run with `CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0`
//! as well as in release mode: optimized builds can hide construction temporaries.

#![cfg(feature = "alloc")]

use ml_dsa::{Keypair, MlDsa44, MlDsa65, MlDsa87, SigningKey, VerifyingKey};

macro_rules! small_stack {
    ($name:ident, $params:ty) => {
        #[test]
        fn $name() {
            let (cloned, public, decoded) = std::thread::Builder::new()
                .stack_size(512 * 1024)
                .spawn(|| {
                    let key = SigningKey::<$params>::from_seed(&[7; 32].into());
                    let cloned = key.clone();
                    drop(key);
                    let public = cloned.verifying_key();
                    let encoded = public.encode();
                    let decoded = VerifyingKey::<$params>::decode(&encoded);
                    (cloned, public, decoded)
                })
                .expect("create construction worker")
                .join()
                .expect("construction worker panicked");

            std::thread::Builder::new()
                .stack_size(512 * 1024)
                .spawn(move || {
                    let signature = cloned
                        .expanded_key()
                        .sign_deterministic(b"message", b"context")
                        .expect("sign");
                    assert!(decoded.verify_with_context(b"message", b"context", &signature));
                    assert!(!decoded.verify_with_context(b"changed", b"context", &signature));
                    assert_eq!(public, decoded);
                })
                .expect("create small-stack worker")
                .join()
                .expect("small-stack worker panicked");
        }
    };
}

small_stack!(ml_dsa_44_small_stack, MlDsa44);
small_stack!(ml_dsa_65_small_stack, MlDsa65);
small_stack!(ml_dsa_87_small_stack, MlDsa87);
