use criterion::{Criterion, criterion_group, criterion_main};
use hybrid_array::{Array, ArraySize};
use ml_dsa::{B32, KeyGen, MlDsa65, Signature, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, TryRngCore};

pub fn rand<L: ArraySize, R: CryptoRng + ?Sized>(rng: &mut R) -> Array<u8, L> {
    let mut val = Array::<u8, L>::default();
    rng.fill_bytes(&mut val);
    val
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = getrandom::SysRng.unwrap_err();
    let xi: B32 = rand(&mut rng);
    let m: B32 = rand(&mut rng);
    let ctx: B32 = rand(&mut rng);

    let kp = MlDsa65::from_seed(&xi);
    let sk = kp.signing_key();
    let vk = kp.verifying_key();
    let sig = sk.sign_deterministic(&m, &ctx).unwrap();

    let sk_bytes = sk.encode();
    let vk_bytes = vk.encode();
    let sig_bytes = sig.encode();

    // Key generation
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let kp = MlDsa65::from_seed(&xi);
            let _sk_bytes = kp.signing_key().encode();
            let _vk_bytes = kp.verifying_key().encode();
        })
    });

    // Signing
    c.bench_function("sign", |b| {
        b.iter(|| {
            let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
            let _sig = sk.sign_deterministic(&m, &ctx);
        })
    });

    // Verifying
    c.bench_function("verify", |b| {
        b.iter(|| {
            let vk = VerifyingKey::<MlDsa65>::decode(&vk_bytes);
            let sig = Signature::<MlDsa65>::decode(&sig_bytes).unwrap();
            let _ver = vk.verify_with_context(&m, &ctx, &sig);
        })
    });

    // Round trip
    c.bench_function("round_trip", |b| {
        b.iter(|| {
            let kp = MlDsa65::from_seed(&xi);
            let sig = kp.signing_key().sign_deterministic(&m, &ctx).unwrap();
            let _ver = kp.verifying_key().verify_with_context(&m, &ctx, &sig);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
