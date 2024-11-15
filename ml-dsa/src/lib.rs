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
mod param;
mod util;

use hybrid_array::typenum::*;

use crate::algebra::*;
use crate::crypto::*;
use crate::param::*;
use crate::util::*;

// TODO(RLB) Clean up this API
pub use crate::param::{
    EncodedSigningKey, EncodedVerificationKey, SigningKeyParams, VerificationKeyParams,
};

/// An ML-DSA signing key
pub struct SigningKey<P: ParameterSet> {
    rho: B32,
    K: B32,
    tr: B64,
    s1: PolynomialVector<P::L>,
    s2: PolynomialVector<P::K>,
    t0: PolynomialVector<P::K>,

    #[allow(dead_code)] // XXX(RLB) Will be used once signing is implemented
    A: NttMatrix<P::K, P::L>,
}

impl<P: ParameterSet> SigningKey<P> {
    /// Deterministically generate a signing key pair from the specified seed
    pub fn key_gen_internal(xi: &B32) -> (VerificationKey<P>, SigningKey<P>)
    where
        P: SigningKeyParams + VerificationKeyParams,
    {
        // Derive seeds
        let mut h = H::default();
        h.absorb(xi);
        h.absorb(&[P::K::U8]);
        h.absorb(&[P::L::U8]);

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

        let mut h = H::default();
        h.absorb(&vk.encode());
        let tr = h.squeeze_new();

        let sk = Self {
            rho,
            K,
            tr,
            s1,
            s2,
            t0,
            A,
        };

        (vk, sk)
    }

    /// Encode the signing key as a byte string
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
}

/// An ML-DSA verification key
pub struct VerificationKey<P: ParameterSet> {
    rho: B32,
    t1: PolynomialVector<P::K>,
}

impl<P: ParameterSet> VerificationKey<P> {
    /// Encode the verification key as a byte string
    // Algorithm 22 pkEncode
    pub fn encode(&self) -> EncodedVerificationKey<P>
    where
        P: VerificationKeyParams,
    {
        let t1 = P::encode_t1(&self.t1);
        P::concat_vk(self.rho.clone(), t1)
    }
}

/// `MlDsa44` is the parameter set for security category 2.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa44;

impl ParameterSet for MlDsa44 {
    type K = U4;
    type L = U4;
    type Eta = U2;
}

/// `MlDsa65` is the parameter set for security category 3.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa65;

impl ParameterSet for MlDsa65 {
    type K = U6;
    type L = U5;
    type Eta = U4;
}

/// `MlKem87` is the parameter set for security category 5.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa87;

impl ParameterSet for MlDsa87 {
    type K = U8;
    type L = U7;
    type Eta = U2;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::param::{SigningKeyParams, VerificationKeyParams};
    use rand::Rng;

    fn key_generation_test<P>()
    where
        P: SigningKeyParams + VerificationKeyParams,
    {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rng.gen();
        let seed: B32 = seed.into();

        let (sk, pk) = SigningKey::<P>::key_gen_internal(&seed);
        let _sk_enc = sk.encode();
        let _pk_enc = pk.encode();
    }

    #[test]
    fn key_generation() {
        key_generation_test::<MlDsa44>();
        key_generation_test::<MlDsa65>();

        // XXX(RLB) Requires new `typenum` values
        // key_generation_test::<MlDsa87>();
    }
}
