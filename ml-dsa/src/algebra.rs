pub(crate) use crate::module_lattice::algebra::Field;
pub(crate) use crate::module_lattice::util::Truncate;
use hybrid_array::{
    ArraySize,
    typenum::{Shleft, U1, U13, Unsigned},
};

use crate::define_field;
use crate::module_lattice::algebra;

define_field!(BaseField, u32, u64, u128, 8_380_417);

pub(crate) type Int = <BaseField as Field>::Int;

pub(crate) type Elem = algebra::Elem<BaseField>;
pub(crate) type Polynomial = algebra::Polynomial<BaseField>;
pub(crate) type Vector<K> = algebra::Vector<BaseField, K>;
pub(crate) type NttPolynomial = algebra::NttPolynomial<BaseField>;
pub(crate) type NttVector<K> = algebra::NttVector<BaseField, K>;
pub(crate) type NttMatrix<K, L> = algebra::NttMatrix<BaseField, K, L>;

// We require modular reduction for three moduli: q, 2^d, and 2 * gamma2.  All three of these are
// greater than sqrt(q), which means that a number reduced mod q will always be less than M^2,
// which means that barrett reduction will work.
pub(crate) trait BarrettReduce: Unsigned {
    const SHIFT: usize;
    const MULTIPLIER: u64;

    fn reduce(x: u32) -> u32 {
        let m = Self::U64;
        let x: u64 = x.into();
        let quotient = (x * Self::MULTIPLIER) >> Self::SHIFT;
        let remainder = x - quotient * m;

        if remainder < m {
            Truncate::truncate(remainder)
        } else {
            Truncate::truncate(remainder - m)
        }
    }
}

impl<M> BarrettReduce for M
where
    M: Unsigned,
{
    #[allow(clippy::as_conversions)]
    const SHIFT: usize = 2 * (M::U64.ilog2() + 1) as usize;
    #[allow(clippy::integer_division_remainder_used)]
    const MULTIPLIER: u64 = (1 << Self::SHIFT) / M::U64;
}

pub(crate) trait Decompose {
    fn decompose<TwoGamma2: Unsigned>(self) -> (Elem, Elem);
}

impl Decompose for Elem {
    // Algorithm 36 Decompose
    fn decompose<TwoGamma2: Unsigned>(self) -> (Elem, Elem) {
        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus::<TwoGamma2>();

        if r_plus - r0 == Elem::new(BaseField::Q - 1) {
            (Elem::new(0), r0 - Elem::new(1))
        } else {
            let mut r1 = r_plus - r0;
            r1.0 /= TwoGamma2::U32;
            (r1, r0)
        }
    }
}

#[allow(clippy::module_name_repetitions)] // I can't think of a better name
pub(crate) trait AlgebraExt: Sized {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self;
    fn infinity_norm(&self) -> Int;
    fn power2round(&self) -> (Self, Self);
    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self;
    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self;
}

impl AlgebraExt for Elem {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        let raw_mod = Elem::new(M::reduce(self.0));
        if raw_mod.0 <= M::U32 >> 1 {
            raw_mod
        } else {
            raw_mod - Elem::new(M::U32)
        }
    }

    // FIPS 204 defines the infinity norm differently for signed vs. unsigned integers:
    //
    // * For w in Z, |w|_\infinity = |w|, the absolute value of w
    // * For w in Z_q, |W|_infinity = |w mod^\pm q|
    //
    // Note that these two definitions are equivalent if |w| < q/2.  This property holds for all of
    // the signed integers used in this crate, so we can safely use the unsigned version.  However,
    // since mod_plus_minus is also unsigned, we need to unwrap the "negative" values.
    fn infinity_norm(&self) -> u32 {
        if self.0 <= BaseField::Q >> 1 {
            self.0
        } else {
            BaseField::Q - self.0
        }
    }

    // Algorithm 35 Power2Round
    //
    // In the specification, this function maps to signed integers rather than modular integers.
    // To avoid the need for a whole separate type for signed integer polynomials, we represent
    // these values using integers mod Q.  This is safe because Q is much larger than 2^13, so
    // there's no risk of overlap between positive numbers (x) and negative numbers (Q-x).
    fn power2round(&self) -> (Self, Self) {
        type D = U13;
        type Pow2D = Shleft<U1, D>;

        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus::<Pow2D>();
        let r1 = Elem::new((r_plus - r0).0 >> D::USIZE);

        (r1, r0)
    }

    // Algorithm 37 HighBits
    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        self.decompose::<TwoGamma2>().0
    }

    // Algorithm 38 LowBits
    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        self.decompose::<TwoGamma2>().1
    }
}

impl AlgebraExt for Polynomial {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(AlgebraExt::mod_plus_minus::<M>).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0.iter().map(AlgebraExt::infinity_norm).max().unwrap()
    }

    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::high_bits::<TwoGamma2>)
                .collect(),
        )
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::low_bits::<TwoGamma2>)
                .collect(),
        )
    }
}

impl<K: ArraySize> AlgebraExt for Vector<K> {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(AlgebraExt::mod_plus_minus::<M>).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0.iter().map(AlgebraExt::infinity_norm).max().unwrap()
    }

    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::high_bits::<TwoGamma2>)
                .collect(),
        )
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::low_bits::<TwoGamma2>)
                .collect(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::integer_division_remainder_used)]
mod test {
    use super::*;

    use crate::{MlDsa65, ParameterSet};

    type Mod = <MlDsa65 as ParameterSet>::TwoGamma2;
    const MOD: u32 = Mod::U32;
    const MOD_ELEM: Elem = Elem::new(MOD);

    #[test]
    fn mod_plus_minus() {
        for x in 0..MOD {
            // BaseField::Q {
            let x = Elem::new(x);
            let x0 = x.mod_plus_minus::<Mod>();

            // Outputs from mod+- should be in the half-open interval (-gamma2, gamma2]
            let positive_bound = x0.0 <= MOD / 2;
            let negative_bound = x0.0 > BaseField::Q - MOD / 2;
            assert!(positive_bound || negative_bound);

            // The output should be equivalent to the input, mod 2 * gamma2.  We add 2 * gamma2
            // before comparing so that both values are "positive", avoiding interactions between
            // the mod-Q and mod-M operations.
            let xn = x + MOD_ELEM;
            let x0n = x0 + MOD_ELEM;
            assert_eq!(xn.0 % MOD, x0n.0 % MOD);
        }
    }

    #[test]
    fn decompose() {
        for x in 0..MOD {
            let x = Elem::new(x);
            let (x1, x0) = x.decompose::<Mod>();

            // The low-order output from decompose() is a mod+- output, optionally minus one.  So
            // they should be in the closed interval [-gamma2, gamma2].
            let positive_bound = x0.0 <= MOD / 2;
            let negative_bound = x0.0 >= BaseField::Q - MOD / 2;
            assert!(positive_bound || negative_bound);

            // The low-order and high-order outputs should combine to form the input.
            let xx = (MOD * x1.0 + x0.0) % BaseField::Q;
            assert_eq!(xx, x.0);
        }
    }
}
