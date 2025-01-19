use criterion::{criterion_group, criterion_main, Criterion};
use hybrid_array::{Array, ArraySize};
use ml_dsa::{KeyGen, MlDsa65, Signature, SigningKey, VerifyingKey, B32};
use rand::{CryptoRng, RngCore};

pub fn rand<L: ArraySize>(rng: &mut (impl RngCore + CryptoRng)) -> Array<u8, L> {
    let mut val = Array::<u8, L>::default();
    rng.fill_bytes(&mut val);
    val
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let xi: B32 = rand(&mut rng);
    let m: B32 = rand(&mut rng);
    let ctx: B32 = rand(&mut rng);

    let kp = MlDsa65::key_gen_internal(&xi);
    let sk = kp.signing_key;
    let vk = kp.verifying_key;
    let sig = sk.sign_deterministic(&m, &ctx).unwrap();

    let sk_bytes = sk.encode();
    let vk_bytes = vk.encode();
    let sig_bytes = sig.encode();

    // Key generation
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let kp = MlDsa65::key_gen_internal(&xi);
            let _sk_bytes = kp.signing_key.encode();
            let _vk_bytes = kp.verifying_key.encode();
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
            let _ver = vk.verify(&m, &ctx, &sig);
        })
    });

    // Round trip
    c.bench_function("round_trip", |b| {
        b.iter(|| {
            let kp = MlDsa65::key_gen_internal(&xi);
            let sig = kp.signing_key.sign_deterministic(&m, &ctx).unwrap();
            let _ver = kp.verifying_key.verify(&m, &ctx, &sig);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
