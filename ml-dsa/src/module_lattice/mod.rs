pub mod algebra {
    use core::fmt::Debug;
    use core::ops::{Add, Mul, Neg, Sub};
    use hybrid_array::{typenum::U256, Array, ArraySize};
    use num_traits::PrimInt;

    pub trait Field: Copy + Default + Debug + PartialEq {
        type Int: PrimInt + Default + Debug;
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

    #[macro_export]
    macro_rules! define_field {
        ($field: ident, $int:ty, $long:ty, $longlong:ty, $q:literal) => {
            #[derive(Copy, Clone, Default, Debug, PartialEq)]
            pub struct $field;

            impl Field for $field {
                type Int = $int;
                type Long = $long;
                type LongLong = $longlong;

                const Q: Self::Int = $q;
                const QL: Self::Long = $q;
                const QLL: Self::LongLong = $q;

                const BARRETT_SHIFT: usize = 2 * (Self::Q.ilog2() + 1) as usize;
                const BARRETT_MULTIPLIER: Self::LongLong = (1 << Self::BARRETT_SHIFT) / Self::QLL;

                fn small_reduce(x: Self::Int) -> Self::Int {
                    if x < Self::Q {
                        x
                    } else {
                        x - Self::Q
                    }
                }

                fn barrett_reduce(x: Self::Long) -> Self::Int {
                    let x: Self::LongLong = x.into();
                    let product = x * Self::BARRETT_MULTIPLIER;
                    let quotient = product >> Self::BARRETT_SHIFT;
                    let remainder = x - quotient * Self::QLL;
                    Self::small_reduce(remainder as Self::Int)
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
        pub const fn new(x: F::Int) -> Self {
            Self(x)
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
        pub const fn new(x: Array<Elem<F>, U256>) -> Self {
            Self(x)
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

    /// A `PolynomialVector` is a vector of polynomials from `R_q` of length `K`.  Vectors can be
    /// added, subtracted, negated, and multiplied by field elements.
    #[derive(Clone, Default, Debug, PartialEq)]
    pub struct PolynomialVector<F: Field, K: ArraySize>(pub Array<Polynomial<F>, K>);

    impl<F: Field, K: ArraySize> PolynomialVector<F, K> {
        pub const fn new(x: Array<Polynomial<F>, K>) -> Self {
            Self(x)
        }
    }

    impl<F: Field, K: ArraySize> Add<&PolynomialVector<F, K>> for &PolynomialVector<F, K> {
        type Output = PolynomialVector<F, K>;

        fn add(self, rhs: &PolynomialVector<F, K>) -> PolynomialVector<F, K> {
            PolynomialVector(
                self.0
                    .iter()
                    .zip(rhs.0.iter())
                    .map(|(x, y)| x + y)
                    .collect(),
            )
        }
    }

    impl<F: Field, K: ArraySize> Sub<&PolynomialVector<F, K>> for &PolynomialVector<F, K> {
        type Output = PolynomialVector<F, K>;

        fn sub(self, rhs: &PolynomialVector<F, K>) -> PolynomialVector<F, K> {
            PolynomialVector(
                self.0
                    .iter()
                    .zip(rhs.0.iter())
                    .map(|(x, y)| x - y)
                    .collect(),
            )
        }
    }

    impl<F: Field, K: ArraySize> Mul<&PolynomialVector<F, K>> for Elem<F> {
        type Output = PolynomialVector<F, K>;

        fn mul(self, rhs: &PolynomialVector<F, K>) -> PolynomialVector<F, K> {
            PolynomialVector(rhs.0.iter().map(|x| self * x).collect())
        }
    }

    impl<F: Field, K: ArraySize> Neg for &PolynomialVector<F, K> {
        type Output = PolynomialVector<F, K>;

        fn neg(self) -> PolynomialVector<F, K> {
            PolynomialVector(self.0.iter().map(|x| -x).collect())
        }
    }

    /// An `NttPolynomial` is a member of the NTT algebra `T_q = Z_q[X]^256` of 256-tuples of field
    /// elements.  NTT polynomials can be added and
    /// subtracted, negated, and multiplied by scalars.
    /// We do not define multiplication of NTT polynomials here.  We also do not define the
    /// mappings between normal polynomials and NTT polynomials (i.e., between `R_q` and `T_q`).
    #[derive(Clone, Default, Debug, PartialEq)]
    pub struct NttPolynomial<F: Field>(pub Array<Elem<F>, U256>);

    impl<F: Field> NttPolynomial<F> {
        pub const fn new(x: Array<Elem<F>, U256>) -> Self {
            Self(x)
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
    /// can be multiplied by NTT polynomials, and "multipled" with each other to produce a dot
    /// product.
    #[derive(Clone, Default, Debug, PartialEq)]
    pub struct NttVector<F: Field, K: ArraySize>(pub Array<NttPolynomial<F>, K>);

    impl<F: Field, K: ArraySize> NttVector<F, K> {
        pub const fn new(x: Array<NttPolynomial<F>, K>) -> Self {
            Self(x)
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
    pub struct NttMatrix<F: Field, K: ArraySize, L: ArraySize>(pub Array<NttVector<F, L>, K>);

    impl<F: Field, K: ArraySize, L: ArraySize> NttMatrix<F, K, L> {
        pub const fn new(x: Array<NttVector<F, L>, K>) -> Self {
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
}
