use crate::{
    algebra::{AlgebraExt, BaseField, Decompose, Elem, NttPolynomial, Polynomial},
    ntt::{Ntt, NttInverse},
    rng::{PrivateRng, PublicRng},
};
use checkct_macros::checkct;
use core::hint::black_box;
use ctutils::{CtLt, CtSelect};
use hybrid_array::Array;
use ml_dsa::{MlDsa44, MlDsa65, MlDsaParams};
use module_lattice::{Field, MultiplyNtt};

// All canonical field elements are reachable. Use hardened selection rather
// than a secret-dependent guard (which would itself fail the analysis).
pub(crate) fn secret_elem() -> Elem {
    let x = PrivateRng.next_u32() & 0x7f_ffff;
    Elem::new(x - BaseField::Q.ct_select(&0, x.ct_lt(&BaseField::Q)))
}

pub(crate) fn secret_poly() -> Polynomial {
    Polynomial::new(Array::from_fn(|_| secret_elem()))
}

macro_rules! probe {
    ($name:ident, $body:expr) => {
        #[checkct]
        pub fn $name() {
            // Generated BINSEC scripts reference both RNG hooks.
            black_box(PublicRng.next_u32());
            black_box($body);
        }
    };
}

probe!(small_reduce, BaseField::small_reduce(PrivateRng.next_u32()));
probe!(field_add, secret_elem() + secret_elem());
probe!(field_sub, secret_elem() - secret_elem());
probe!(field_mul, secret_elem() * secret_elem());
probe!(field_neg, -secret_elem());
probe!(power2round, secret_elem().power2round());
probe!(decompose_44, decompose::<MlDsa44>());
probe!(decompose_65_87, decompose::<MlDsa65>());
probe!(infinity_norm, secret_poly().infinity_norm());
probe!(ntt, secret_poly().ntt());
probe!(
    ntt_inverse,
    NttPolynomial::new(secret_poly().0).ntt_inverse()
);
probe!(
    multiply_ntt,
    BaseField::multiply_ntt(
        &NttPolynomial::new(secret_poly().0),
        &NttPolynomial::new(secret_poly().0),
    )
);

fn decompose<P: MlDsaParams>() -> (Elem, Elem) {
    secret_elem().decompose::<P::TwoGamma2>()
}
