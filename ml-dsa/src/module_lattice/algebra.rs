use super::util::Truncate;

use core::fmt::Debug;
use core::ops::{Add, Mul, Neg, Sub};
use hybrid_array::{Array, ArraySize, typenum::U256};
use num_traits::PrimInt;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub trait Field: Copy + Default + Debug + PartialEq {
    type Int: PrimInt + Default + Debug + From<u8> + Into<u128> + Into<Self::Long> + Truncate<u128>;
    type Long: PrimInt + From<Self::Int>;
    type LongLong: PrimInt;

    const Q: Self::Int;
    const QL: Self::Long;
    const QLL: Self::LongLong;

    const BARRETT_SHIFT: usize;
    const BARRETT_MULTIPLIER: Self::LongLong;

    fn small_reduce(x: Self::Int) -> Self::Int;
    fn barrett_reduce(x: Self::Long) -> Self::Int;
}

/// The `define_field` macro creates a zero-sized struct and an implementation of the Field trait
/// for that struct.  The caller must specify:
///
/// * `$field`: The name of the zero-sized struct to be created
/// * `$q`: The prime number that defines the field.
/// * `$int`: The primitive integer type to be used to represent members of the field
/// * `$long`: The primitive integer type to be used to represent products of two field members.
///   This type should have roughly twice the bits of `$int`.
/// * `$longlong`: The primitive integer type to be used to represent products of three field
///   members. This type should have roughly four times the bits of `$int`.
#[macro_export]
macro_rules! define_field {
    ($field:ident, $int:ty, $long:ty, $longlong:ty, $q:literal) => {
        #[derive(Copy, Clone, Default, Debug, PartialEq)]
        pub struct $field;

        impl Field for $field {
            type Int = $int;
            type Long = $long;
            type LongLong = $longlong;

            const Q: Self::Int = $q;
            const QL: Self::Long = $q;
            const QLL: Self::LongLong = $q;

            #[allow(clippy::as_conversions)]
            const BARRETT_SHIFT: usize = 2 * (Self::Q.ilog2() + 1) as usize;
            #[allow(clippy::integer_division_remainder_used)]
            const BARRETT_MULTIPLIER: Self::LongLong = (1 << Self::BARRETT_SHIFT) / Self::QLL;

            fn small_reduce(x: Self::Int) -> Self::Int {
                if x < Self::Q { x } else { x - Self::Q }
            }

            fn barrett_reduce(x: Self::Long) -> Self::Int {
                let x: Self::LongLong = x.into();
                let product = x * Self::BARRETT_MULTIPLIER;
                let quotient = product >> Self::BARRETT_SHIFT;
                let remainder = x - quotient * Self::QLL;
                Self::small_reduce(Truncate::truncate(remainder))
            }
        }
    };
}

/// An `Elem` is a member of the specified prime-order field.  Elements can be added,
/// subtracted, multiplied, and negated, and the overloaded operators will ensure both that the
/// integer values remain in the field, and that the reductions are done efficiently.  For
/// addition and subtraction, a simple conditional subtraction is used; for multiplication,
/// Barrett reduction.
#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct Elem<F: Field>(pub F::Int);

impl<F: Field> Elem<F> {
    pub(crate) const fn new(x: F::Int) -> Self {
        Self(x)
    }
}

#[cfg(feature = "zeroize")]
impl<F: Field> Zeroize for Elem<F>
where
    F::Int: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<F: Field> Neg for Elem<F> {
    type Output = Elem<F>;

    fn neg(self) -> Elem<F> {
        Elem(F::small_reduce(F::Q - self.0))
    }
}

impl<F: Field> Add<Elem<F>> for Elem<F> {
    type Output = Elem<F>;

    fn add(self, rhs: Elem<F>) -> Elem<F> {
        Elem(F::small_reduce(self.0 + rhs.0))
    }
}

impl<F: Field> Sub<Elem<F>> for Elem<F> {
    type Output = Elem<F>;

    fn sub(self, rhs: Elem<F>) -> Elem<F> {
        Elem(F::small_reduce(self.0 + F::Q - rhs.0))
    }
}

impl<F: Field> Mul<Elem<F>> for Elem<F> {
    type Output = Elem<F>;

    fn mul(self, rhs: Elem<F>) -> Elem<F> {
        let lhs: F::Long = self.0.into();
        let rhs: F::Long = rhs.0.into();
        let prod = lhs * rhs;
        Elem(F::barrett_reduce(prod))
    }
}

/// A `Polynomial` is a member of the ring `R_q = Z_q[X] / (X^256)` of degree-256 polynomials
/// over the finite field with prime order `q`.  Polynomials can be added, subtracted, negated,
/// and multiplied by field elements.  We do not define multiplication of polynomials here.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Polynomial<F: Field>(pub Array<Elem<F>, U256>);

impl<F: Field> Polynomial<F> {
    pub(crate) const fn new(x: Array<Elem<F>, U256>) -> Self {
        Self(x)
    }
}

#[cfg(feature = "zeroize")]
impl<F: Field> Zeroize for Polynomial<F>
where
    F::Int: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<F: Field> Add<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn add(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        Polynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x + y)
                .collect(),
        )
    }
}

impl<F: Field> Sub<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn sub(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        Polynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x - y)
                .collect(),
        )
    }
}

impl<F: Field> Mul<&Polynomial<F>> for Elem<F> {
    type Output = Polynomial<F>;

    fn mul(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        Polynomial(rhs.0.iter().map(|&x| self * x).collect())
    }
}

impl<F: Field> Neg for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn neg(self) -> Polynomial<F> {
        Polynomial(self.0.iter().map(|&x| -x).collect())
    }
}

/// A `Vector` is a vector of polynomials from `R_q` of length `K`.  Vectors can be
/// added, subtracted, negated, and multiplied by field elements.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Vector<F: Field, K: ArraySize>(pub Array<Polynomial<F>, K>);

impl<F: Field, K: ArraySize> Vector<F, K> {
    pub(crate) const fn new(x: Array<Polynomial<F>, K>) -> Self {
        Self(x)
    }
}

#[cfg(feature = "zeroize")]
impl<F: Field, K: ArraySize> Zeroize for Vector<F, K>
where
    F::Int: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<F: Field, K: ArraySize> Add<&Vector<F, K>> for &Vector<F, K> {
    type Output = Vector<F, K>;

    fn add(self, rhs: &Vector<F, K>) -> Vector<F, K> {
        Vector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x + y)
                .collect(),
        )
    }
}

impl<F: Field, K: ArraySize> Sub<&Vector<F, K>> for &Vector<F, K> {
    type Output = Vector<F, K>;

    fn sub(self, rhs: &Vector<F, K>) -> Vector<F, K> {
        Vector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x - y)
                .collect(),
        )
    }
}

impl<F: Field, K: ArraySize> Mul<&Vector<F, K>> for Elem<F> {
    type Output = Vector<F, K>;

    fn mul(self, rhs: &Vector<F, K>) -> Vector<F, K> {
        Vector(rhs.0.iter().map(|x| self * x).collect())
    }
}

impl<F: Field, K: ArraySize> Neg for &Vector<F, K> {
    type Output = Vector<F, K>;

    fn neg(self) -> Vector<F, K> {
        Vector(self.0.iter().map(|x| -x).collect())
    }
}

/// An `NttPolynomial` is a member of the NTT algebra `T_q = Z_q[X]^256` of 256-tuples of field
/// elements.  NTT polynomials can be added and
/// subtracted, negated, and multiplied by scalars.
/// We do not define multiplication of NTT polynomials here.  We also do not define the
/// mappings between normal polynomials and NTT polynomials (i.e., between `R_q` and `T_q`).
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct NttPolynomial<F: Field>(pub Array<Elem<F>, U256>);

impl<F: Field> NttPolynomial<F> {
    pub(crate) const fn new(x: Array<Elem<F>, U256>) -> Self {
        Self(x)
    }
}

#[cfg(feature = "zeroize")]
impl<F: Field> Zeroize for NttPolynomial<F>
where
    F::Int: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<F: Field> Add<&NttPolynomial<F>> for &NttPolynomial<F> {
    type Output = NttPolynomial<F>;

    fn add(self, rhs: &NttPolynomial<F>) -> NttPolynomial<F> {
        NttPolynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x + y)
                .collect(),
        )
    }
}

impl<F: Field> Sub<&NttPolynomial<F>> for &NttPolynomial<F> {
    type Output = NttPolynomial<F>;

    fn sub(self, rhs: &NttPolynomial<F>) -> NttPolynomial<F> {
        NttPolynomial(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x - y)
                .collect(),
        )
    }
}

impl<F: Field> Mul<&NttPolynomial<F>> for Elem<F> {
    type Output = NttPolynomial<F>;

    fn mul(self, rhs: &NttPolynomial<F>) -> NttPolynomial<F> {
        NttPolynomial(rhs.0.iter().map(|&x| self * x).collect())
    }
}

impl<F: Field> Neg for &NttPolynomial<F> {
    type Output = NttPolynomial<F>;

    fn neg(self) -> NttPolynomial<F> {
        NttPolynomial(self.0.iter().map(|&x| -x).collect())
    }
}

/// An `NttVector` is a vector of polynomials from `T_q` of length `K`.  NTT vectors can be
/// added and subtracted.  If multiplication is defined for NTT polynomials, then NTT vectors
/// can be multiplied by NTT polynomials, and "multiplied" with each other to produce a dot
/// product.
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct NttVector<F: Field, K: ArraySize>(pub Array<NttPolynomial<F>, K>);

impl<F: Field, K: ArraySize> NttVector<F, K> {
    pub(crate) const fn new(x: Array<NttPolynomial<F>, K>) -> Self {
        Self(x)
    }
}

#[cfg(feature = "zeroize")]
impl<F: Field, K: ArraySize> Zeroize for NttVector<F, K>
where
    F::Int: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<F: Field, K: ArraySize> Add<&NttVector<F, K>> for &NttVector<F, K> {
    type Output = NttVector<F, K>;

    fn add(self, rhs: &NttVector<F, K>) -> NttVector<F, K> {
        NttVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x + y)
                .collect(),
        )
    }
}

impl<F: Field, K: ArraySize> Sub<&NttVector<F, K>> for &NttVector<F, K> {
    type Output = NttVector<F, K>;

    fn sub(self, rhs: &NttVector<F, K>) -> NttVector<F, K> {
        NttVector(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(x, y)| x - y)
                .collect(),
        )
    }
}

impl<F: Field, K: ArraySize> Mul<&NttVector<F, K>> for &NttPolynomial<F>
where
    for<'a> &'a NttPolynomial<F>: Mul<&'a NttPolynomial<F>, Output = NttPolynomial<F>>,
{
    type Output = NttVector<F, K>;

    fn mul(self, rhs: &NttVector<F, K>) -> NttVector<F, K> {
        NttVector(rhs.0.iter().map(|x| self * x).collect())
    }
}

impl<F: Field, K: ArraySize> Mul<&NttVector<F, K>> for &NttVector<F, K>
where
    for<'a> &'a NttPolynomial<F>: Mul<&'a NttPolynomial<F>, Output = NttPolynomial<F>>,
{
    type Output = NttPolynomial<F>;

    fn mul(self, rhs: &NttVector<F, K>) -> NttPolynomial<F> {
        self.0
            .iter()
            .zip(rhs.0.iter())
            .map(|(x, y)| x * y)
            .fold(NttPolynomial::default(), |x, y| &x + &y)
    }
}

/// A K x L matrix of NTT-domain polynomials.  Each vector represents a row of the matrix, so that
/// multiplying on the right just requires iteration.  Multiplication on the right by vectors
/// is the only defined operation, and is only defined when multiplication of NTT polynomials
/// is defined.
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct NttMatrix<F: Field, K: ArraySize, L: ArraySize>(pub Array<NttVector<F, L>, K>);

impl<F: Field, K: ArraySize, L: ArraySize> NttMatrix<F, K, L> {
    pub(crate) const fn new(x: Array<NttVector<F, L>, K>) -> Self {
        Self(x)
    }
}

impl<F: Field, K: ArraySize, L: ArraySize> Mul<&NttVector<F, L>> for &NttMatrix<F, K, L>
where
    for<'a> &'a NttPolynomial<F>: Mul<&'a NttPolynomial<F>, Output = NttPolynomial<F>>,
{
    type Output = NttVector<F, K>;

    fn mul(self, rhs: &NttVector<F, L>) -> NttVector<F, K> {
        NttVector(self.0.iter().map(|x| x * rhs).collect())
    }
}
