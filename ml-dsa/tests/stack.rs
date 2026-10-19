//! Regression test for large key-construction and cloning temporaries.

// Debug builds need substantially more stack; this limit targets optimized builds with allocation.
#![cfg(all(feature = "alloc", not(debug_assertions)))]
#![allow(clippy::unwrap_used, reason = "tests")]

use ml_dsa::{ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey};
use std::thread;

fn lifecycle<P: MlDsaParams + PartialEq>() {
    let sk = SigningKey::<P>::from_seed(&Seed::default());
    assert!(sk == sk.clone());
    let vk = sk.expanded_key().verifying_key();
    assert!(vk == vk.clone());
    assert!(vk == ml_dsa::VerifyingKey::<P>::decode(&vk.encode()));

    #[allow(deprecated)]
    let imported = ExpandedSigningKey::<P>::from_expanded(&sk.expanded_key().to_expanded());
    assert!(sk.expanded_key() == &imported);
    let sig = imported.sign_deterministic(b"small stack", &[]).unwrap();
    assert!(vk.verify_with_context(b"small stack", &[], &sig));
}

#[test]
fn key_lifecycle_on_small_stack() {
    // This includes thread startup and all nested calls, with headroom for platform differences.
    thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            lifecycle::<MlDsa44>();
            lifecycle::<MlDsa65>();
            lifecycle::<MlDsa87>();
        })
        .unwrap()
        .join()
        .unwrap();
}
