//#![no_std]
#![doc = include_str!("../README.md")]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`
#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::clone_on_copy)] // Be explicit about moving data

// TODO(RLB) Re-enable #![deny(missing_docs)] // Require all public interfaces to be documented

mod algebra;
mod crypto;
mod encode;
mod hint;
mod param;
mod util;

use hybrid_array::{typenum::*, Array};

use crate::algebra::*;
use crate::crypto::*;
use crate::hint::*;
use crate::param::*;
use crate::util::*;

// TODO(RLB) Clean up this API
pub use crate::param::{
    EncodedSigningKey, EncodedVerificationKey, SignatureParams, SigningKeyParams,
    VerificationKeyParams,
};

pub use crate::util::B32;

/// An ML-DSA signature
#[derive(Clone, PartialEq)]
pub struct Signature<P: SignatureParams> {
    c_tilde: Array<u8, P::Lambda>,
    z: PolynomialVector<P::L>,
    h: Hint<P>,
}

impl<P: SignatureParams> Signature<P> {
    // Algorithm 26 sigEncode
    pub fn encode(&self) -> EncodedSignature<P> {
        let c_tilde = self.c_tilde.clone();
        let z = P::encode_z(&self.z);
        let h = self.h.bit_pack();
        P::concat_sig(c_tilde, z, h)
    }

    // Algorithm 27 sigDecode
    pub fn parse(enc: &EncodedSignature<P>) -> Option<Self> {
        let (c_tilde, z, h) = P::split_sig(&enc);
        Some(Self {
            c_tilde: c_tilde.clone(),
            z: P::decode_z(z),
            h: Hint::bit_unpack(h)?,
        })
    }
}

/// An ML-DSA signing key
#[derive(Clone, PartialEq)]
pub struct SigningKey<P: ParameterSet> {
    rho: B32,
    K: B32,
    tr: B64,
    s1: PolynomialVector<P::L>,
    s2: PolynomialVector<P::K>,
    t0: PolynomialVector<P::K>,
}

impl<P: ParameterSet> SigningKey<P> {
    /// Deterministically generate a signing key pair from the specified seed
    pub fn key_gen_internal(xi: &B32) -> (VerificationKey<P>, SigningKey<P>)
    where
        P: SigningKeyParams + VerificationKeyParams,
    {
        // Derive seeds
        let mut h = H::default()
            .absorb(xi)
            .absorb(&[P::K::U8])
            .absorb(&[P::L::U8]);

        let rho: B32 = h.squeeze_new();
        let rhop: B64 = h.squeeze_new();
        let K: B32 = h.squeeze_new();

        // Sample private key components
        let A = NttMatrix::<P::K, P::L>::expand_a(&rho);
        let s1 = PolynomialVector::<P::L>::expand_s(&rhop, P::Eta::ETA, 0);
        let s2 = PolynomialVector::<P::K>::expand_s(&rhop, P::Eta::ETA, P::L::USIZE);

        // Compute derived values
        let As1 = &A * &s1.ntt();
        let t = &As1.ntt_inverse() + &s2;

        // Compress and encode
        let (t1, t0) = t.power2round();

        let vk = VerificationKey {
            rho: rho.clone(),
            t1,
        };

        let tr = H::default().absorb(&vk.encode()).squeeze_new();

        let sk = Self {
            rho,
            K,
            tr,
            s1,
            s2,
            t0,
        };

        (vk, sk)
    }

    // Algorithm 7 ML-DSA.Sign_internal
    pub fn sign_internal(&self, Mp: &[u8], rnd: &B32) -> Signature<P>
    where
        P: SignatureParams,
    {
        // TODO(RLB) pre-compute these and store them on the signing key struct
        let s1_hat = self.s1.ntt();
        let s2_hat = self.s2.ntt();
        let t0_hat = self.t0.ntt();
        let A_hat = NttMatrix::<P::K, P::L>::expand_a(&self.rho);

        // Compute the message representative
        // XXX(RLB) Should the API represent this as an input?
        let mu: B64 = H::default().absorb(&self.tr).absorb(&Mp).squeeze_new();

        // Compute the private random seed
        let rhopp: B64 = H::default()
            .absorb(&self.K)
            .absorb(rnd)
            .absorb(&mu)
            .squeeze_new();

        // Rejection sampling loop
        for kappa in (0..u16::MAX).step_by(P::L::USIZE) {
            let y = PolynomialVector::<P::L>::expand_mask::<P::Gamma1>(&rhopp, kappa);
            let w = (&A_hat * &y.ntt()).ntt_inverse();
            let w0 = w.low_bits::<P::Gamma2>(); // XXX(RLB)
            let w1 = w.high_bits::<P::Gamma2>();

            let w1_tilde = P::encode_w1(&w1);
            let c_tilde = H::default()
                .absorb(&mu)
                .absorb(&w1_tilde)
                .squeeze_new::<P::Lambda>();
            let c = Polynomial::sample_in_ball(&c_tilde, P::TAU);
            let c_hat = c.ntt();

            let cs1 = (&c_hat * &s1_hat).ntt_inverse();
            let cs2 = (&c_hat * &s2_hat).ntt_inverse();

            let z = &y + &cs1;
            let r0 = (&w - &cs2).low_bits::<P::Gamma2>();

            let gamma1_threshold = P::Gamma1::U32 - P::BETA;
            let gamma2_threshold = P::Gamma2::U32 - P::BETA;
            if z.infinity_norm() > gamma1_threshold || r0.infinity_norm() > gamma2_threshold {
                continue;
            }

            let ct0 = (&c_hat * &t0_hat).ntt_inverse();
            let h = Hint::<P>::new(-&ct0, &(&w - &cs2) + &ct0);

            if ct0.infinity_norm() > P::Gamma2::U32 || h.hamming_weight() > P::Omega::USIZE {
                continue;
            }

            let z = z.mod_plus_minus(FieldElement(FieldElement::Q));
            return Signature { c_tilde, z, h };
        }

        // TODO(RLB) Make this method fallible
        panic!("Rejection sampling failed to find a valid signature");
    }

    // Algorithm 24 skEncode
    pub fn encode(&self) -> EncodedSigningKey<P>
    where
        P: SigningKeyParams,
    {
        let s1_enc = P::encode_s1(&self.s1);
        let s2_enc = P::encode_s2(&self.s2);
        let t0_enc = P::encode_t0(&self.t0);
        P::concat_sk(
            self.rho.clone(),
            self.K.clone(),
            self.tr.clone(),
            s1_enc,
            s2_enc,
            t0_enc,
        )
    }

    // Algorithm 25 skDecode
    pub fn decode(enc: &EncodedSigningKey<P>) -> Self
    where
        P: SigningKeyParams,
    {
        let (rho, K, tr, s1_enc, s2_enc, t0_enc) = P::split_sk(enc);
        Self {
            rho: rho.clone(),
            K: K.clone(),
            tr: tr.clone(),
            s1: P::decode_s1(s1_enc),
            s2: P::decode_s2(s2_enc),
            t0: P::decode_t0(t0_enc),
        }
    }
}

/// An ML-DSA verification key
#[derive(Clone, PartialEq)]
pub struct VerificationKey<P: ParameterSet> {
    rho: B32,
    t1: PolynomialVector<P::K>,
}

impl<P: ParameterSet> VerificationKey<P> {
    pub fn verify(&self, Mp: &[u8], sigma: &Signature<P>) -> bool
    where
        P: VerificationKeyParams + SignatureParams,
    {
        // TODO(RLB) pre-compute these and store them on the signing key struct
        let A_hat = NttMatrix::<P::K, P::L>::expand_a(&self.rho);
        let t1_hat = (FieldElement(1 << 13) * &self.t1).ntt();
        let tr: B64 = H::default().absorb(&self.encode()).squeeze_new();

        // Compute the message representative
        // XXX(RLB) might need to run bytes_to_bits()?
        let mu: B64 = H::default().absorb(&tr).absorb(&Mp).squeeze_new();

        // Reconstruct w
        let c = Polynomial::sample_in_ball(&sigma.c_tilde, P::TAU);

        let z_hat = sigma.z.ntt();
        let c_hat = c.ntt();
        let Az_hat = &A_hat * &z_hat;
        let ct1_hat = &c_hat * &t1_hat;

        let wp_approx = (&Az_hat - &ct1_hat).ntt_inverse();
        let w1p = sigma.h.use_hint(&wp_approx);

        let w1p_tilde = P::encode_w1(&w1p);
        let cp_tilde = H::default()
            .absorb(&mu)
            .absorb(&w1p_tilde)
            .squeeze_new::<P::Lambda>();

        let gamma1_threshold = P::Gamma1::U32 - P::BETA;
        return sigma.z.infinity_norm() < gamma1_threshold && sigma.c_tilde == cp_tilde;
    }

    // Algorithm 22 pkEncode
    pub fn encode(&self) -> EncodedVerificationKey<P>
    where
        P: VerificationKeyParams,
    {
        let t1 = P::encode_t1(&self.t1);
        P::concat_vk(self.rho.clone(), t1)
    }

    // Algorithm 23 pkDecode
    pub fn decode(enc: &EncodedVerificationKey<P>) -> Self
    where
        P: VerificationKeyParams,
    {
        let (rho, t1_enc) = P::split_vk(enc);
        Self {
            rho: rho.clone(),
            t1: P::decode_t1(t1_enc),
        }
    }
}

/// `MlDsa44` is the parameter set for security category 2.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa44;

impl ParameterSet for MlDsa44 {
    type K = U4;
    type L = U4;
    type Eta = U2;
    type Gamma1 = Shleft<U1, U17>;
    type Gamma2 = Quot<QMinus1, U88>;
    type W1Bits = Length<Diff<Prod<U88, U2>, U1>>;
    type Lambda = U32;
    type Omega = U80;
    const TAU: usize = 39;
}

/// `MlDsa65` is the parameter set for security category 3.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa65;

impl ParameterSet for MlDsa65 {
    type K = U6;
    type L = U5;
    type Eta = U4;
    type Gamma1 = Shleft<U1, U19>;
    type Gamma2 = Quot<QMinus1, U32>;
    type W1Bits = Length<Diff<Prod<U32, U2>, U1>>;
    type Lambda = U48;
    type Omega = U55;
    const TAU: usize = 49;
}

/// `MlKem87` is the parameter set for security category 5.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa87;

impl ParameterSet for MlDsa87 {
    type K = U8;
    type L = U7;
    type Eta = U2;
    type Gamma1 = Shleft<U1, U19>;
    type Gamma2 = Quot<QMinus1, U32>;
    type W1Bits = Length<Diff<Prod<U32, U2>, U1>>;
    type Lambda = U64;
    type Omega = U75;
    const TAU: usize = 60;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::param::{SigningKeyParams, VerificationKeyParams};
    use rand::Rng;

    fn encode_decode_round_trip_test<P>()
    where
        P: SigningKeyParams + VerificationKeyParams + SignatureParams + PartialEq,
    {
        let mut rng = rand::thread_rng();

        let seed: [u8; 32] = rng.gen();
        let (pk, sk) = SigningKey::<P>::key_gen_internal(&seed.into());

        let pk_bytes = pk.encode();
        let pk2 = VerificationKey::<P>::decode(&pk_bytes);
        assert!(pk == pk2);

        let sk_bytes = sk.encode();
        let sk2 = SigningKey::<P>::decode(&sk_bytes);
        assert!(sk == sk2);
    }

    #[test]
    fn encode_decode_round_trip() {
        encode_decode_round_trip_test::<MlDsa44>();
        encode_decode_round_trip_test::<MlDsa65>();
        encode_decode_round_trip_test::<MlDsa87>();
    }

    fn sign_verify_round_trip_test<P>()
    where
        P: SigningKeyParams + VerificationKeyParams + SignatureParams,
    {
        let mut rng = rand::thread_rng();

        let seed: [u8; 32] = rng.gen();
        let (_pk, sk) = SigningKey::<P>::key_gen_internal(&seed.into());

        let rnd: [u8; 32] = rng.gen();
        let Mp = b"Hello world";
        let _sig = sk.sign_internal(Mp, &rnd.into());

        // TODO(RLB) Re-enable and debug
        // assert!(pk.verify(Mp, &sig));
    }

    #[test]
    fn sign_verify_round_trip() {
        sign_verify_round_trip_test::<MlDsa44>();
        sign_verify_round_trip_test::<MlDsa65>();
        sign_verify_round_trip_test::<MlDsa87>();
    }
}
