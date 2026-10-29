//! Signing-stage probes. No intermediate value is declassified.
use crate::{
    B64, MlDsaParams,
    algebra::{AlgebraExt, NttPolynomial, NttVector, Vector},
    driver::secret_poly,
    param::MaskSamplingSize,
    params::Params,
    rng::{PrivateRng, PublicRng},
    sampling::expand_mask_xof,
    signing_steps,
};
use checkct_macros::checkct;
use core::hint::black_box;
use hybrid_array::{Array, ArraySize};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};

fn secret_vector<K: ArraySize>() -> Vector<K> {
    Vector::new(Array::from_fn(|_| secret_poly()))
}

fn secret_ntt_vector<K: ArraySize>() -> NttVector<K> {
    NttVector::new(Array::from_fn(|_| NttPolynomial::new(secret_poly().0)))
}

fn mask_xof<P: MlDsaParams>() {
    let mut rho = B64::default();
    PrivateRng.fill_bytes(&mut rho);
    let mut nonce = [0; 2];
    PublicRng.fill_bytes(&mut nonce);
    black_box(expand_mask_xof::<P::Gamma1>(
        &rho,
        u16::from_le_bytes(nonce),
    ));
}

fn mask_unpack<P: MlDsaParams>() {
    let mut bytes = Array::<u8, <P::Gamma1 as MaskSamplingSize>::SampleSize>::default();
    PrivateRng.fill_bytes(&mut bytes);
    black_box(P::Gamma1::unpack(&bytes));
}

fn response<P: MlDsaParams>() {
    let signing_steps::Response { z, cs2, r0 } = signing_steps::response::<P>(
        &secret_vector(),
        &secret_vector(),
        &NttPolynomial::new(secret_poly().0),
        &secret_ntt_vector(),
        &secret_ntt_vector(),
    );
    // Check both complete norm computations, stopping before rejection branches.
    black_box((z.infinity_norm(), r0.infinity_norm(), z, cs2));
}

fn hint_polynomials<P: MlDsaParams>() {
    let (ct0, r) = signing_steps::hint_polynomials::<P>(
        &secret_vector(),
        &secret_vector(),
        &NttPolynomial::new(secret_poly().0),
        &secret_ntt_vector(),
    );
    black_box((ct0.infinity_norm(), -&ct0, r));
}

fn hint<P: MlDsaParams>() {
    let h = crate::hint::Hint::<P>::new(&secret_vector(), &secret_vector());
    // Use fresh secret inputs at this boundary to keep Thumb-2 solver queries
    // tractable. No input is declassified or constrained to an accepted attempt.
    black_box((h.hamming_weight(), h));
}

macro_rules! probes {
    ($p:ty, $response:ident, $polynomials:ident, $hint:ident) => {
        #[checkct]
        pub fn $response() {
            black_box(PublicRng.next_u32());
            response::<Params<$p>>();
        }
        #[checkct]
        pub fn $polynomials() {
            black_box(PublicRng.next_u32());
            hint_polynomials::<Params<$p>>();
        }
        #[checkct]
        pub fn $hint() {
            black_box(PublicRng.next_u32());
            hint::<Params<$p>>();
        }
    };
}

probes!(
    MlDsa44,
    signing_response_44,
    signing_hint_polynomials_44,
    signing_hint_44
);

probes!(
    MlDsa65,
    signing_response_65,
    signing_hint_polynomials_65,
    signing_hint_65
);

probes!(
    MlDsa87,
    signing_response_87,
    signing_hint_polynomials_87,
    signing_hint_87
);

// Gamma1 and its encoding size are shared by ML-DSA-65 and ML-DSA-87.
macro_rules! mask_probes {
    ($p:ty, $xof:ident, $unpack:ident) => {
        #[checkct]
        pub fn $xof() {
            mask_xof::<Params<$p>>();
        }
        #[checkct]
        pub fn $unpack() {
            black_box(PublicRng.next_u32());
            mask_unpack::<Params<$p>>();
        }
    };
}
mask_probes!(MlDsa44, signing_mask_xof_44, signing_mask_unpack_44);
mask_probes!(MlDsa65, signing_mask_xof_65_87, signing_mask_unpack_65_87);
