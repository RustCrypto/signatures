//! Straight-line computations inside one signing attempt.
//!
//! Keep the rejection decisions in the caller so these computations can be
//! checked with all intermediate values still classified as secret.

use crate::{
    MlDsaParams,
    algebra::{AlgebraExt, NttPolynomial, NttVector, Vector},
    ntt::NttInverse,
};

/// Intermediate values used by the first rejection check and hint computation.
pub(crate) struct Response<P: MlDsaParams> {
    pub(crate) z: Vector<P::L>,
    pub(crate) cs2: Vector<P::K>,
    pub(crate) r0: Vector<P::K>,
}

/// Compute the response `z`, `cs2`, and the low bits `r0` checked before hint generation.
#[inline]
pub(crate) fn response<P: MlDsaParams>(
    y: &Vector<P::L>,
    w: &Vector<P::K>,
    c_hat: &NttPolynomial,
    s1_hat: &NttVector<P::L>,
    s2_hat: &NttVector<P::K>,
) -> Response<P> {
    let cs1 = (c_hat * s1_hat).ntt_inverse();
    let cs2 = (c_hat * s2_hat).ntt_inverse();
    let z = y + &cs1;
    let r0 = (w - &cs2).low_bits::<P::TwoGamma2>();
    Response { z, cs2, r0 }
}

/// Compute `ct0` and `w - cs2 + ct0` for hint construction.
#[inline]
pub(crate) fn hint_polynomials<P: MlDsaParams>(
    w: &Vector<P::K>,
    cs2: &Vector<P::K>,
    c_hat: &NttPolynomial,
    t0_hat: &NttVector<P::K>,
) -> (Vector<P::K>, Vector<P::K>) {
    let ct0 = (c_hat * t0_hat).ntt_inverse();
    let w_cs2_ct0 = &(w - cs2) + &ct0;
    (ct0, w_cs2_ct0)
}
