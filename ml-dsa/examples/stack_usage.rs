//! Probe stack requirements in a separate process: a stack overflow aborts the process.
//!
//! Run with `cargo run -p ml-dsa --release --example stack_usage -- 87 keygen 524288`.
//! Stack sizes and compiler optimizations vary between platforms; compare with the same toolchain.

use core::hint::black_box;
use ml_dsa::{
    ExpandedSigningKey, Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey,
    VerifyingKey,
};
use std::{env, thread};

#[inline(never)]
fn keygen<P: MlDsaParams>() {
    black_box(SigningKey::<P>::from_seed(black_box(&Seed::default())));
}

fn probe<P: MlDsaParams + Send + Sync + 'static>(operation: &str, stack_size: usize) {
    let worker = thread::Builder::new().stack_size(stack_size);
    let handle = match operation {
        "keygen" => worker.spawn(keygen::<P>),
        "clone" => {
            let sk = SigningKey::<P>::from_seed(&Seed::default());
            worker.spawn(move || {
                black_box(black_box(&sk).clone());
            })
        }
        "decode" => {
            let sk = SigningKey::<P>::from_seed(&Seed::default());
            let enc = sk.verifying_key().encode();
            worker.spawn(move || {
                black_box(VerifyingKey::<P>::decode(black_box(&enc)));
            })
        }
        "derive" => {
            let sk = SigningKey::<P>::from_seed(&Seed::default());
            worker.spawn(move || {
                black_box(sk.expanded_key().verifying_key());
            })
        }
        "import" => {
            let sk = SigningKey::<P>::from_seed(&Seed::default());
            #[allow(deprecated)]
            let enc = sk.expanded_key().to_expanded();
            worker.spawn(move || {
                #[allow(deprecated)]
                black_box(ExpandedSigningKey::<P>::from_expanded(black_box(&enc)));
            })
        }
        "sign" => {
            let sk = SigningKey::<P>::from_seed(&Seed::default());
            worker.spawn(move || {
                black_box(
                    sk.expanded_key()
                        .sign_deterministic(black_box(b"stack probe"), &[]),
                )
                .expect("signing failed");
            })
        }
        "verify" => {
            let sk = SigningKey::<P>::from_seed(&Seed::default());
            let vk = sk.verifying_key().clone();
            let sig = sk
                .expanded_key()
                .sign_deterministic(b"stack probe", &[])
                .expect("signing failed");
            worker.spawn(move || {
                assert!(vk.verify_with_context(black_box(b"stack probe"), &[], black_box(&sig)));
            })
        }
        _ => panic!("operation must be keygen, clone, decode, derive, import, sign, or verify"),
    };
    handle
        .expect("spawning thread failed")
        .join()
        .expect("worker failed");
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "usage: stack_usage <44|65|87> <operation> <stack bytes>"
    );
    let stack_size = args[3].parse().expect("invalid stack size");
    match args[1].as_str() {
        "44" => probe::<MlDsa44>(&args[2], stack_size),
        "65" => probe::<MlDsa65>(&args[2], stack_size),
        "87" => probe::<MlDsa87>(&args[2], stack_size),
        _ => panic!("parameter set must be 44, 65, or 87"),
    }
}
