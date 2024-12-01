use core::ops::{Add, Mul, Neg, Sub};
use hybrid_array::{
    typenum::{Unsigned, U256},
    Array,
};

use crate::param::ArraySize;
use crate::util::Truncate;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub type Integer = u32;

/// An element of GF(q)
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct FieldElement(pub Integer);

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl FieldElement {
    pub const Q: Integer = 8380417;
    pub const Q64: u64 = Self::Q as u64;
    pub const ONE: Self = Self(1);
    pub const MINUS_ONE: Self = Self(Self::Q - 1);

    fn mod_plus_minus(&self, m: Self) -> Self {
        let raw_mod = Self(self.0 % m.0);
        if raw_mod.0 <= m.0 >> 1 {
            raw_mod
        } else {
            raw_mod - m
        }
    }

    // Algorithm 35 Power2Round
    //
    // In the specification, this function maps to signed integers rather than modular integers.
    // To avoid the need for a whole separate type for signed integer polynomials, we represent
    // these values using integers mod Q.  This is safe because Q is much larger than 2^13, so
    // there's no risk of overlap between positive numbers (x) and negative numbers (Q-x).
    fn power2round(&self) -> (Self, Self) {
        const D: Integer = 13;
        const POW_2_D: Integer = 1 << D;

        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus(Self(POW_2_D));
        let r1 = FieldElement((r_plus - r0).0 >> D);

        (r1, r0)
    }

    // Algorithm 36 Decompose
    pub fn decompose<Gamma2: Unsigned>(&self) -> (Self, Self) {
        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus(Self(2 * Gamma2::U32));

        if r_plus - r0 == FieldElement(FieldElement::Q - 1) {
            (FieldElement(0), r0 - FieldElement(1))
        } else {
            let mut r1 = r_plus - r0;
            r1.0 /= 2 * Gamma2::U32;
            (r1, r0)
        }
    }

    // Algorithm 37 HighBits
    pub fn high_bits<Gamma2: Unsigned>(&self) -> Self {
        self.decompose::<Gamma2>().0
    }

    // Algorithm 38 LowBits
    fn low_bits<Gamma2: Unsigned>(&self) -> Self {
        self.decompose::<Gamma2>().1
    }

    // FIPS 204 defines the infinity norm differently for signed vs. unsigned integers:
    //
    // * For w in Z, |w|_\infinity = |w|, the absolute value of w
    // * For w in Z_q, |W|_infinity = |w mod^\pm q|
    //
    // Note that these two definitions are equivalent if |w| < q/2.  This property holds for all of
    // the signed integers used in this crate, so we can safely use the unsigned version.  However,
    // since mod_plus_minus is also unsigned, we need to unwrap the "negative" values.
    pub fn infinity_norm(&self) -> u32 {
        if self.0 <= Self::Q >> 1 {
            self.0
        } else {
            Self::Q - self.0
        }
    }

    // A fast modular reduction for small numbers `x < 2*q`
    fn small_reduce(x: u32) -> u32 {
        if x < Self::Q {
            x
        } else {
            x - Self::Q
        }
    }

    fn barrett_reduce(x: u64) -> u32 {
        // TODO(RLB) Actually implement Barrett reduction here.
        (x % Self::Q64).truncate()

        /*
        let product = u64::from(x) * Self::BARRETT_MULTIPLIER;
        let quotient = (product >> Self::BARRETT_SHIFT).truncate();
        let remainder = x - quotient * Self::Q32;
        Self::small_reduce(remainder.truncate())
        */
    }
}

impl From<FieldElement> for u128 {
    fn from(x: FieldElement) -> u128 {
        x.0.into()
    }
}

impl From<u128> for FieldElement {
    fn from(x: u128) -> FieldElement {
        FieldElement(x.truncate())
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(Self::small_reduce(self.0 + rhs.0))
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        // Guard against underflow if `rhs` is too large
        Self(Self::small_reduce(self.0 + Self::Q - rhs.0))
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        let x = u64::from(self.0);
        let y = u64::from(rhs.0);
        Self(Self::barrett_reduce(x * y))
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        Self(Self::Q - self.0)
    }
}

/// An element of the ring `R_q`, i.e., a polynomial over `Z_q` of degree 255
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Polynomial(pub Array<FieldElement, U256>);

impl Polynomial {
    fn mod_plus_minus(&self, m: FieldElement) -> Self {
        Self(self.0.iter().map(|x| x.mod_plus_minus(m)).collect())
    }

    fn high_bits<Gamma2: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(|x| x.high_bits::<Gamma2>()).collect())
    }

    fn low_bits<Gamma2: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(|x| x.low_bits::<Gamma2>()).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0.iter().map(|x| x.infinity_norm()).max().unwrap()
    }

    // Algorithm 35 Power2Round
    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }
}

impl Add<&Polynomial> for &Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x + y)
                .collect(),
        )
    }
}

impl Sub<&Polynomial> for &Polynomial {
    type Output = Polynomial;

    fn sub(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x - y)
                .collect(),
        )
    }
}

impl Neg for &Polynomial {
    type Output = Polynomial;

    fn neg(self) -> Polynomial {
        Polynomial(self.0.iter().map(|&x| -x).collect())
    }
}

impl Mul<&Polynomial> for FieldElement {
    type Output = Polynomial;

    fn mul(self, rhs: &Polynomial) -> Polynomial {
        Polynomial(rhs.0.iter().map(|&x| self * x).collect())
    }
}

/// A vector of polynomials of length `k`
#[derive(Clone, Default, Debug, PartialEq)]
pub struct PolynomialVector<K: ArraySize>(pub Array<Polynomial, K>);

impl<K: ArraySize> PolynomialVector<K> {
    pub fn mod_plus_minus(&self, m: FieldElement) -> Self {
        Self(self.0.iter().map(|x| x.mod_plus_minus(m)).collect())
    }

    pub fn high_bits<Gamma2: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(|x| x.high_bits::<Gamma2>()).collect())
    }

    pub fn low_bits<Gamma2: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(|x| x.low_bits::<Gamma2>()).collect())
    }

    pub fn infinity_norm(&self) -> u32 {
        self.0.iter().map(|x| x.infinity_norm()).max().unwrap()
    }

    // Algorithm 35 Power2Round
    pub fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }
}

impl<K: ArraySize> Add<&PolynomialVector<K>> for &PolynomialVector<K> {
    type Output = PolynomialVector<K>;

    fn add(self, rhs: &PolynomialVector<K>) -> PolynomialVector<K> {
        PolynomialVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x + y)
                .collect(),
        )
    }
}

impl<K: ArraySize> Sub<&PolynomialVector<K>> for &PolynomialVector<K> {
    type Output = PolynomialVector<K>;

    fn sub(self, rhs: &PolynomialVector<K>) -> PolynomialVector<K> {
        PolynomialVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x - y)
                .collect(),
        )
    }
}

impl<K: ArraySize> Neg for &PolynomialVector<K> {
    type Output = PolynomialVector<K>;

    fn neg(self) -> PolynomialVector<K> {
        PolynomialVector(self.0.iter().map(|x| -x).collect())
    }
}

impl<K: ArraySize> Mul<&PolynomialVector<K>> for FieldElement {
    type Output = PolynomialVector<K>;

    fn mul(self, rhs: &PolynomialVector<K>) -> PolynomialVector<K> {
        PolynomialVector(rhs.0.iter().map(|x| self * x).collect())
    }
}

/// An element of the ring `T_q`, i.e., a tuple of 128 elements of the direct sum components of `T_q`.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttPolynomial(pub Array<FieldElement, U256>);

impl NttPolynomial {}

#[cfg(feature = "zeroize")]
impl Zeroize for NttPolynomial {
    fn zeroize(&mut self) {
        for fe in self.0.iter_mut() {
            fe.zeroize()
        }
    }
}

// Algorithm 44 AddNTT
impl Add<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    fn add(self, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x + y)
                .collect(),
        )
    }
}

impl Sub<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    fn sub(self, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x - y)
                .collect(),
        )
    }
}

impl From<Array<FieldElement, U256>> for NttPolynomial {
    fn from(f: Array<FieldElement, U256>) -> NttPolynomial {
        NttPolynomial(f)
    }
}

impl From<NttPolynomial> for Array<FieldElement, U256> {
    fn from(f_hat: NttPolynomial) -> Array<FieldElement, U256> {
        f_hat.0
    }
}

/// A vector of K NTT-domain polynomials
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttVector<K: ArraySize>(pub Array<NttPolynomial, K>);

#[cfg(feature = "zeroize")]
impl<K> Zeroize for NttVector<K>
where
    K: ArraySize,
{
    fn zeroize(&mut self) {
        for poly in self.0.iter_mut() {
            poly.zeroize();
        }
    }
}

// Algorithm 46 AddVectorNTT
impl<K: ArraySize> Add<&NttVector<K>> for &NttVector<K> {
    type Output = NttVector<K>;

    fn add(self, rhs: &NttVector<K>) -> NttVector<K> {
        NttVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x + y)
                .collect(),
        )
    }
}

impl<K: ArraySize> Sub<&NttVector<K>> for &NttVector<K> {
    type Output = NttVector<K>;

    fn sub(self, rhs: &NttVector<K>) -> NttVector<K> {
        NttVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x - y)
                .collect(),
        )
    }
}

// Algorithm 47 ScalarVectorNTT
impl<K: ArraySize> Mul<&NttVector<K>> for &NttPolynomial {
    type Output = NttVector<K>;

    fn mul(self, rhs: &NttVector<K>) -> NttVector<K> {
        NttVector(rhs.0.iter().map(|x| self * x).collect())
    }
}

// Dot product of two polynomial vectors.  Used in MatrixVectorNTT.
//
// Incorporates:
// Algorithm 47 ScalarVectorNTT
impl<K: ArraySize> Mul<&NttVector<K>> for &NttVector<K> {
    type Output = NttPolynomial;

    fn mul(self, rhs: &NttVector<K>) -> NttPolynomial {
        self.0
            .iter()
            .zip(rhs.0.iter())
            .map(|(x, y)| x * y)
            .fold(NttPolynomial::default(), |x, y| &x + &y)
    }
}

/// A K x L matrix of NTT-domain polynomials.  Each vector represents a row of the matrix, so that
/// multiplying on the right just requires iteration.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttMatrix<K: ArraySize, L: ArraySize>(pub Array<NttVector<L>, K>);

impl<K: ArraySize, L: ArraySize> Mul<&NttVector<L>> for &NttMatrix<K, L> {
    type Output = NttVector<K>;

    fn mul(self, rhs: &NttVector<L>) -> NttVector<K> {
        NttVector(self.0.iter().map(|x| x * rhs).collect())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn polynomial_ops() {
        let f = Polynomial(Array::from_fn(|i| FieldElement(i as Integer)));
        let g = Polynomial(Array::from_fn(|i| FieldElement(2 * i as Integer)));
        let sum = Polynomial(Array::from_fn(|i| FieldElement(3 * i as Integer)));
        assert_eq!((&f + &g), sum);
        assert_eq!((&sum - &g), f);
        assert_eq!(FieldElement(3) * &f, sum);
    }
}
