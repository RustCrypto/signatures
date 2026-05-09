//! ML-DSA benchmarks.

#![allow(clippy::unwrap_used, reason = "benchmarks")]
#![allow(missing_docs, reason = "benchmarks")]

use criterion::{Criterion, criterion_group, criterion_main};
use ml_dsa::{
    B32, ExpandedSigningKey, Generate, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey,
};

/// ML-DSA benchmarks.
#[allow(deprecated)] // TODO(tarcieri): stop using expanded signing keys
fn criterion_benchmark(c: &mut Criterion) {
    let xi = B32::generate();
    let m = B32::generate();
    let ctx = B32::generate();

    let kp = SigningKey::<MlDsa65>::from_seed(&xi);
    let sk = kp.expanded_key();
    let vk = kp.verifying_key();
    let sig = sk.sign_deterministic(&m, &ctx).unwrap();

    let sk_bytes = sk.to_expanded();
    let vk_bytes = vk.encode();
    let sig_bytes = sig.encode();

    // Key generation
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let kp = SigningKey::<MlDsa65>::generate();
            let _sk_bytes = kp.expanded_key().to_expanded();
            let _vk_bytes = kp.verifying_key().encode();
        });
    });

    // Signing
    c.bench_function("sign", |b| {
        b.iter(|| {
            let sk = ExpandedSigningKey::<MlDsa65>::from_expanded(&sk_bytes);
            let _sig = sk.sign_deterministic(&m, &ctx);
        });
    });

    // Verifying
    c.bench_function("verify", |b| {
        b.iter(|| {
            let vk = VerifyingKey::<MlDsa65>::decode(&vk_bytes);
            let sig = Signature::<MlDsa65>::decode(&sig_bytes).unwrap();
            let _ver = vk.verify_with_context(&m, &ctx, &sig);
        });
    });

    // Round trip
    c.bench_function("round_trip", |b| {
        b.iter(|| {
            let kp = SigningKey::<MlDsa65>::from_seed(&xi);
            let sig = kp.expanded_key().sign_deterministic(&m, &ctx).unwrap();
            let _ver = kp.verifying_key().verify_with_context(&m, &ctx, &sig);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
