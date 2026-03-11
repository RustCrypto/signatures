//! Property-based tests for the `ml-dsa` crate.

macro_rules! signature_round_trip_encode {
    ($alg:ident, $sig:expr) => {{
        let sig_enc = $sig.encode();
        let sig_dec_result = Signature::<$alg>::decode(&sig_enc);
        prop_assert_eq!(&sig_dec_result, &Some($sig));
        sig_dec_result.unwrap()
    }};
}

macro_rules! mldsa_proptests {
    ($name:ident, $alg:ident) => {
        mod $name {
            use ml_dsa::{
                KeyGen, Signature,
                signature::{DigestSigner, DigestVerifier, digest::Update},
                $alg,
            };
            use proptest::{collection, prelude::*};

            #[cfg(feature = "rand_core")]
            use ml_dsa::signature::RandomizedDigestSigner;

            proptest! {
                #[test]
                fn round_trip_test(
                    seed in any::<[u8; 32]>(),
                    msg in collection::vec(0u8..u8::MAX, 0..65536),
                    rnd in any::<[u8; 32]>()
                ) {
                    let kp = $alg::from_seed(&seed.into());
                    let sk = kp.signing_key();
                    let vk = kp.verifying_key();

                    let sig = sk.sign_internal(&[&msg], &rnd.into());
                    let sig_dec = signature_round_trip_encode!($alg, sig);
                    assert!(vk.verify_internal(&msg, &sig_dec));
                }

                #[test]
                fn round_trip_digest_test(
                    seed in any::<[u8; 32]>(),
                    msg in collection::vec(0u8..u8::MAX, 0..65536),
                ) {
                    let kp = $alg::from_seed(&seed.into());
                    let sk = kp.signing_key();
                    let vk = kp.verifying_key();

                    let sig = sk.sign_digest(|digest| digest.update(&msg));
                    let sig_dec = signature_round_trip_encode!($alg, sig);
                    let verify_result = vk.verify_digest(|digest| Ok(digest.update(&msg)), &sig_dec);
                    assert!(verify_result.is_ok());
                }

                #[cfg(feature = "rand_core")]
                #[test]
                fn round_trip_randomized_digest_test(
                    seed in any::<[u8; 32]>(),
                    msg in collection::vec(0u8..u8::MAX, 0..65536),
                ) {
                    let kp = $alg::from_seed(&seed.into());
                    let sk = kp.signing_key();
                    let vk = kp.verifying_key();

                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                    let sig = sk.sign_digest_with_rng(&mut rng, |digest| digest.update(&msg));
                    let sig_dec = signature_round_trip_encode!($alg, sig);
                    let verify_result = vk.verify_digest(|digest| Ok(digest.update(&msg)), &sig_dec);
                    assert!(verify_result.is_ok());
                }
            }
        }
    };
}

mldsa_proptests!(mldsa44, MlDsa44);
mldsa_proptests!(mldsa65, MlDsa65);
mldsa_proptests!(mldsa87, MlDsa87);
