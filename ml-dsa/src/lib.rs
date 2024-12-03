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
mod ntt;
mod param;
mod sampling;
mod util;

// TODO(RLB) Move module to an independent crate shared with ml_kem
mod module_lattice;

use hybrid_array::{typenum::*, Array};

use crate::algebra::*;
use crate::crypto::*;
use crate::hint::*;
use crate::ntt::*;
use crate::param::*;
use crate::sampling::*;
use crate::util::*;

// TODO(RLB) Clean up this API
pub use crate::param::{
    EncodedSignature, EncodedSigningKey, EncodedVerificationKey, SignatureParams, SigningKeyParams,
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
    pub fn decode(enc: &EncodedSignature<P>) -> Option<Self> {
        let (c_tilde, z, h) = P::split_sig(&enc);

        let c_tilde = c_tilde.clone();
        let z = P::decode_z(z);
        let h = Hint::bit_unpack(h)?;

        if z.infinity_norm() >= P::GAMMA1_MINUS_BETA {
            return None;
        }

        Some(Self { c_tilde, z, h })
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

    // Derived values
    s1_hat: NttVector<P::L>,
    s2_hat: NttVector<P::K>,
    t0_hat: NttVector<P::K>,
    A_hat: NttMatrix<P::K, P::L>,
}

impl<P: ParameterSet> SigningKey<P> {
    fn new(
        rho: B32,
        K: B32,
        tr: B64,
        s1: PolynomialVector<P::L>,
        s2: PolynomialVector<P::K>,
        t0: PolynomialVector<P::K>,
        A_hat: Option<NttMatrix<P::K, P::L>>,
    ) -> Self {
        let A_hat = A_hat.unwrap_or_else(|| expand_a(&rho));
        let s1_hat = s1.ntt();
        let s2_hat = s2.ntt();
        let t0_hat = t0.ntt();

        Self {
            rho,
            K,
            tr,
            s1,
            s2,
            t0,

            s1_hat,
            s2_hat,
            t0_hat,
            A_hat,
        }
    }

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
        let A_hat = expand_a::<P::K, P::L>(&rho);
        let s1 = expand_s::<P::L>(&rhop, P::Eta::ETA, 0);
        let s2 = expand_s::<P::K>(&rhop, P::Eta::ETA, P::L::USIZE);

        // Compute derived values
        let As1_hat = &A_hat * &s1.ntt();
        let t = &As1_hat.ntt_inverse() + &s2;

        // Compress and encode
        let (t1, t0) = t.power2round();

        let vk = VerificationKey::new(rho, t1, Some(A_hat.clone()), None);
        let sk = Self::new(rho, K, vk.tr.clone(), s1, s2, t0, Some(A_hat));

        (vk, sk)
    }

    // Algorithm 7 ML-DSA.Sign_internal
    pub fn sign_internal(&self, Mp: &[u8], rnd: &B32) -> Signature<P>
    where
        P: SignatureParams,
    {
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
            let y = expand_mask::<P::L, P::Gamma1>(&rhopp, kappa);
            let w = (&self.A_hat * &y.ntt()).ntt_inverse();
            let w1 = w.high_bits::<P::TwoGamma2>();

            let w1_tilde = P::encode_w1(&w1);
            let c_tilde = H::default()
                .absorb(&mu)
                .absorb(&w1_tilde)
                .squeeze_new::<P::Lambda>();
            let c = sample_in_ball(&c_tilde, P::TAU);
            let c_hat = c.ntt();

            let cs1 = (&c_hat * &self.s1_hat).ntt_inverse();
            let cs2 = (&c_hat * &self.s2_hat).ntt_inverse();

            let z = &y + &cs1;
            let r0 = (&w - &cs2).low_bits::<P::TwoGamma2>();

            if z.infinity_norm() >= P::GAMMA1_MINUS_BETA
                || r0.infinity_norm() >= P::GAMMA2_MINUS_BETA
            {
                continue;
            }

            let ct0 = (&c_hat * &self.t0_hat).ntt_inverse();
            let h = Hint::<P>::new(-&ct0, &(&w - &cs2) + &ct0);

            if ct0.infinity_norm() >= P::TwoGamma2::U32 / 2 || h.hamming_weight() > P::Omega::USIZE
            {
                continue;
            }

            let z = z.mod_plus_minus::<SpecQ>();
            return Signature { c_tilde, z, h };
        }

        // XXX(RLB) We could be more parsimonious about the number of iterations here, and still
        // have an overwhelming probability of success.
        // XXX(RLB) I still don't love panicking.  Maybe we should expose the fact that this method
        // can fail?
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
        Self::new(
            rho.clone(),
            K.clone(),
            tr.clone(),
            P::decode_s1(s1_enc),
            P::decode_s2(s2_enc),
            P::decode_t0(t0_enc),
            None,
        )
    }
}

/// An ML-DSA verification key
#[derive(Clone, PartialEq)]
pub struct VerificationKey<P: ParameterSet> {
    rho: B32,
    t1: PolynomialVector<P::K>,

    // Derived values
    A_hat: NttMatrix<P::K, P::L>,
    t1_2d_hat: NttVector<P::K>,
    tr: B64,
}

impl<P: VerificationKeyParams> VerificationKey<P> {
    pub fn verify_internal(&self, Mp: &[u8], sigma: &Signature<P>) -> bool
    where
        P: SignatureParams,
    {
        // Compute the message representative
        let mu: B64 = H::default().absorb(&self.tr).absorb(&Mp).squeeze_new();

        // Reconstruct w
        let c = sample_in_ball(&sigma.c_tilde, P::TAU);

        let z_hat = sigma.z.ntt();
        let c_hat = c.ntt();
        let Az_hat = &self.A_hat * &z_hat;
        let ct1_2d_hat = &c_hat * &self.t1_2d_hat;

        let wp_approx = (&Az_hat - &ct1_2d_hat).ntt_inverse();
        let w1p = sigma.h.use_hint(&wp_approx);

        let w1p_tilde = P::encode_w1(&w1p);
        let cp_tilde = H::default()
            .absorb(&mu)
            .absorb(&w1p_tilde)
            .squeeze_new::<P::Lambda>();

        sigma.c_tilde == cp_tilde
    }

    fn encode_internal(rho: &B32, t1: &PolynomialVector<P::K>) -> EncodedVerificationKey<P> {
        let t1_enc = P::encode_t1(t1);
        P::concat_vk(rho.clone(), t1_enc)
    }

    fn new(
        rho: B32,
        t1: PolynomialVector<P::K>,
        A_hat: Option<NttMatrix<P::K, P::L>>,
        enc: Option<EncodedVerificationKey<P>>,
    ) -> Self {
        let A_hat = A_hat.unwrap_or_else(|| expand_a(&rho));
        let enc = enc.unwrap_or_else(|| Self::encode_internal(&rho, &t1));

        let t1_2d_hat = (FieldElement::new(1 << 13) * &t1).ntt();
        let tr: B64 = H::default().absorb(&enc).squeeze_new();

        Self {
            rho,
            t1,
            A_hat,
            t1_2d_hat,
            tr,
        }
    }

    // Algorithm 22 pkEncode
    pub fn encode(&self) -> EncodedVerificationKey<P> {
        Self::encode_internal(&self.rho, &self.t1)
    }

    // Algorithm 23 pkDecode
    pub fn decode(enc: &EncodedVerificationKey<P>) -> Self {
        let (rho, t1_enc) = P::split_vk(enc);
        let t1 = P::decode_t1(t1_enc);
        Self::new(rho.clone(), t1, None, Some(enc.clone()))
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
    type TwoGamma2 = Quot<QMinus1, U44>;
    type W1Bits = Length<Diff<Quot<U88, U2>, U1>>;
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
    type TwoGamma2 = Quot<QMinus1, U16>;
    type W1Bits = Length<Diff<Quot<U32, U2>, U1>>;
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
    type TwoGamma2 = Quot<QMinus1, U16>;
    type W1Bits = Length<Diff<Quot<U32, U2>, U1>>;
    type Lambda = U64;
    type Omega = U75;
    const TAU: usize = 60;
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    #[test]
    fn output_sizes() {
        //           priv pub  sig
        // ML-DSA-44 2560 1312 2420
        // ML-DSA-65 4032 1952 3309
        // ML-DSA-87 4896 2592 4627
        assert_eq!(SigningKeySize::<MlDsa44>::USIZE, 2560);
        assert_eq!(VerificationKeySize::<MlDsa44>::USIZE, 1312);
        assert_eq!(SignatureSize::<MlDsa44>::USIZE, 2420);

        assert_eq!(SigningKeySize::<MlDsa65>::USIZE, 4032);
        assert_eq!(VerificationKeySize::<MlDsa65>::USIZE, 1952);
        assert_eq!(SignatureSize::<MlDsa65>::USIZE, 3309);

        assert_eq!(SigningKeySize::<MlDsa87>::USIZE, 4896);
        assert_eq!(VerificationKeySize::<MlDsa87>::USIZE, 2592);
        assert_eq!(SignatureSize::<MlDsa87>::USIZE, 4627);
    }

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

        let sig = sk.sign_internal(&[0, 1, 2, 3], (&[0u8; 32]).into());
        let sig_bytes = sig.encode();
        println!("sig_bytes: {:?}", hex::encode(&sig_bytes));
        let sig2 = Signature::<P>::decode(&sig_bytes).unwrap();
        assert!(sig == sig2);
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
        let (pk, sk) = SigningKey::<P>::key_gen_internal(&seed.into());

        let rnd: [u8; 32] = rng.gen();
        let Mp = b"Hello world";
        let sig = sk.sign_internal(Mp, &rnd.into());

        assert!(pk.verify_internal(Mp, &sig));
    }

    #[test]
    fn sign_verify_round_trip() {
        sign_verify_round_trip_test::<MlDsa44>();
        sign_verify_round_trip_test::<MlDsa65>();
        sign_verify_round_trip_test::<MlDsa87>();
    }
}
