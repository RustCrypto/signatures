// XXX(RLB) There are no unit tests in this module right now, because the algebra and encode/decode
// routines all require a field, and the concrete field definitions are down in the dependent
// modules.  Maybe we should pull the field definitions up into this module so that we can verify
// that everything works.  That might also let us make private some of the tools used to build
// things up.

pub mod algebra {
    use super::util::Truncate;

    use core::fmt::Debug;
    use core::ops::{Add, Mul, Neg, Sub};
    use hybrid_array::{typenum::U256, Array, ArraySize};
    use num_traits::PrimInt;

    pub trait Field: Copy + Default + Debug + PartialEq {
        type Int: PrimInt
            + Default
            + Debug
            + From<u8>
            + Into<u128>
            + Into<Self::Long>
            + Truncate<u128>;
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

    /// A `Vector` is a vector of polynomials from `R_q` of length `K`.  Vectors can be
    /// added, subtracted, negated, and multiplied by field elements.
    #[derive(Clone, Default, Debug, PartialEq)]
    pub struct Vector<F: Field, K: ArraySize>(pub Array<Polynomial<F>, K>);

    impl<F: Field, K: ArraySize> Vector<F, K> {
        pub const fn new(x: Array<Polynomial<F>, K>) -> Self {
            Self(x)
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

pub mod util {
    use core::mem::ManuallyDrop;
    use core::ops::{Div, Mul, Rem};
    use core::ptr;
    use hybrid_array::{typenum::*, Array, ArraySize};

    /// Safely truncate an unsigned integer value to shorter representation
    pub trait Truncate<T> {
        fn truncate(x: T) -> Self;
    }

    macro_rules! define_truncate {
        ($from:ident, $to:ident) => {
            impl Truncate<$from> for $to {
                fn truncate(x: $from) -> $to {
                    // This line is marked unsafe because the `unwrap_unchecked` call is UB when its
                    // `self` argument is `Err`.  It never will be, because we explicitly zeroize the
                    // high-order bits before converting.  We could have used `unwrap()`, but chose to
                    // avoid the possibility of panic.
                    unsafe { (x & $from::from($to::MAX)).try_into().unwrap_unchecked() }
                }
            }
        };
    }

    define_truncate!(u128, u32);
    define_truncate!(u64, u32);
    define_truncate!(usize, u8);
    define_truncate!(usize, u16);

    /// Defines a sequence of sequences that can be merged into a bigger overall seequence
    pub trait Flatten<T, M: ArraySize> {
        type OutputSize: ArraySize;

        fn flatten(self) -> Array<T, Self::OutputSize>;
    }

    impl<T, N, M> Flatten<T, Prod<M, N>> for Array<Array<T, M>, N>
    where
        N: ArraySize,
        M: ArraySize + Mul<N>,
        Prod<M, N>: ArraySize,
    {
        type OutputSize = Prod<M, N>;

        // This is the reverse transmute between [T; K*N] and [[T; K], M], which is guaranteed to be
        // safe by the Rust memory layout of these types.
        fn flatten(self) -> Array<T, Self::OutputSize> {
            let whole = ManuallyDrop::new(self);
            unsafe { ptr::read(whole.as_ptr().cast()) }
        }
    }

    /// Defines a sequence that can be split into a sequence of smaller sequences of uniform size
    pub trait Unflatten<M>
    where
        M: ArraySize,
    {
        type Part;

        fn unflatten(self) -> Array<Self::Part, M>;
    }

    impl<T, N, M> Unflatten<M> for Array<T, N>
    where
        T: Default,
        N: ArraySize + Div<M> + Rem<M, Output = U0>,
        M: ArraySize,
        Quot<N, M>: ArraySize,
    {
        type Part = Array<T, Quot<N, M>>;

        // This requires some unsafeness, but it is the same as what is done in Array::split.
        // Basically, this is doing transmute between [T; K*N] and [[T; K], M], which is guaranteed to
        // be safe by the Rust memory layout of these types.
        fn unflatten(self) -> Array<Self::Part, M> {
            let part_size = Quot::<N, M>::USIZE;
            let whole = ManuallyDrop::new(self);
            Array::from_fn(|i| unsafe { ptr::read(whole.as_ptr().add(i * part_size).cast()) })
        }
    }

    impl<'a, T, N, M> Unflatten<M> for &'a Array<T, N>
    where
        T: Default,
        N: ArraySize + Div<M> + Rem<M, Output = U0>,
        M: ArraySize,
        Quot<N, M>: ArraySize,
    {
        type Part = &'a Array<T, Quot<N, M>>;

        // This requires some unsafeness, but it is the same as what is done in Array::split.
        // Basically, this is doing transmute between [T; K*N] and [[T; K], M], which is guaranteed to
        // be safe by the Rust memory layout of these types.
        fn unflatten(self) -> Array<Self::Part, M> {
            let part_size = Quot::<N, M>::USIZE;
            let mut ptr: *const T = self.as_ptr();
            Array::from_fn(|_i| unsafe {
                let part = &*(ptr.cast());
                ptr = ptr.add(part_size);
                part
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn flatten() {
            let flat: Array<u8, _> = Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
            let unflat2: Array<Array<u8, _>, _> = Array([
                Array([1, 2]),
                Array([3, 4]),
                Array([5, 6]),
                Array([7, 8]),
                Array([9, 10]),
            ]);
            let unflat5: Array<Array<u8, _>, _> =
                Array([Array([1, 2, 3, 4, 5]), Array([6, 7, 8, 9, 10])]);

            // Flatten
            let actual = unflat2.flatten();
            assert_eq!(flat, actual);

            let actual = unflat5.flatten();
            assert_eq!(flat, actual);

            // Unflatten
            let actual: Array<Array<u8, U2>, U5> = flat.unflatten();
            assert_eq!(unflat2, actual);

            let actual: Array<Array<u8, U5>, U2> = flat.unflatten();
            assert_eq!(unflat5, actual);

            // Unflatten on references
            let actual: Array<&Array<u8, U2>, U5> = (&flat).unflatten();
            for (i, part) in actual.iter().enumerate() {
                assert_eq!(&unflat2[i], *part);
            }

            let actual: Array<&Array<u8, U5>, U2> = (&flat).unflatten();
            for (i, part) in actual.iter().enumerate() {
                assert_eq!(&unflat5[i], *part);
            }
        }
    }
}

pub mod encode {
    use core::fmt::Debug;
    use core::ops::{Div, Mul, Rem};
    use hybrid_array::{typenum::*, Array};
    use num_traits::One;

    use super::algebra::*;
    use super::util::{Flatten, Truncate, Unflatten};

    /// An array length with other useful properties
    pub trait ArraySize: hybrid_array::ArraySize + PartialEq + Debug {}

    impl<T> ArraySize for T where T: hybrid_array::ArraySize + PartialEq + Debug {}

    /// An integer that can describe encoded polynomials.
    pub trait EncodingSize: ArraySize {
        type EncodedPolynomialSize: ArraySize;
        type ValueStep: ArraySize;
        type ByteStep: ArraySize;
    }

    type EncodingUnit<D> = Quot<Prod<D, U8>, Gcf<D, U8>>;

    pub type EncodedPolynomialSize<D> = <D as EncodingSize>::EncodedPolynomialSize;
    pub type EncodedPolynomial<D> = Array<u8, EncodedPolynomialSize<D>>;

    impl<D> EncodingSize for D
    where
        D: ArraySize + Mul<U8> + Gcd<U8> + Mul<U32>,
        Prod<D, U32>: ArraySize,
        Prod<D, U8>: Div<Gcf<D, U8>>,
        EncodingUnit<D>: Div<D> + Div<U8>,
        Quot<EncodingUnit<D>, D>: ArraySize,
        Quot<EncodingUnit<D>, U8>: ArraySize,
    {
        type EncodedPolynomialSize = Prod<D, U32>;
        type ValueStep = Quot<EncodingUnit<D>, D>;
        type ByteStep = Quot<EncodingUnit<D>, U8>;
    }

    type DecodedValue<F> = Array<Elem<F>, U256>;

    /// An integer that can describe encoded vectors.
    pub trait VectorEncodingSize<K>: EncodingSize
    where
        K: ArraySize,
    {
        type EncodedVectorSize: ArraySize;

        fn flatten(polys: Array<EncodedPolynomial<Self>, K>) -> EncodedVector<Self, K>;
        fn unflatten(vec: &EncodedVector<Self, K>) -> Array<&EncodedPolynomial<Self>, K>;
    }

    pub type EncodedVectorSize<D, K> =
        <D as VectorEncodingSize<K>>::EncodedVectorSize;
    pub type EncodedVector<D, K> = Array<u8, EncodedVectorSize<D, K>>;

    impl<D, K> VectorEncodingSize<K> for D
    where
        D: EncodingSize,
        K: ArraySize,
        D::EncodedPolynomialSize: Mul<K>,
        Prod<D::EncodedPolynomialSize, K>:
            ArraySize + Div<K, Output = D::EncodedPolynomialSize> + Rem<K, Output = U0>,
    {
        type EncodedVectorSize = Prod<D::EncodedPolynomialSize, K>;

        fn flatten(polys: Array<EncodedPolynomial<Self>, K>) -> EncodedVector<Self, K> {
            polys.flatten()
        }

        fn unflatten(vec: &EncodedVector<Self, K>) -> Array<&EncodedPolynomial<Self>, K> {
            vec.unflatten()
        }
    }

    // FIPS 203: Algorithm 4 ByteEncode_d
    // FIPS 204: Algorithm 16 SimpleBitPack
    fn byte_encode<F: Field, D: EncodingSize>(vals: &DecodedValue<F>) -> EncodedPolynomial<D> {
        let val_step = D::ValueStep::USIZE;
        let byte_step = D::ByteStep::USIZE;

        let mut bytes = EncodedPolynomial::<D>::default();

        let vc = vals.chunks(val_step);
        let bc = bytes.chunks_mut(byte_step);
        for (v, b) in vc.zip(bc) {
            let mut x = 0u128;
            for (j, vj) in v.iter().enumerate() {
                let vj: u128 = vj.0.into();
                x |= vj << (D::USIZE * j);
            }

            let xb = x.to_le_bytes();
            b.copy_from_slice(&xb[..byte_step]);
        }

        bytes
    }

    // FIPS 203: Algorithm 5 ByteDecode_d(F)
    // FIPS 204: Algorithm 18 SimpleBitUnpack
    fn byte_decode<F: Field, D: EncodingSize>(bytes: &EncodedPolynomial<D>) -> DecodedValue<F> {
        let val_step = D::ValueStep::USIZE;
        let byte_step = D::ByteStep::USIZE;
        let mask = (F::Int::one() << D::USIZE) - F::Int::one();

        let mut vals = DecodedValue::default();

        let vc = vals.chunks_mut(val_step);
        let bc = bytes.chunks(byte_step);
        for (v, b) in vc.zip(bc) {
            let mut xb = [0u8; 16];
            xb[..byte_step].copy_from_slice(b);

            let x = u128::from_le_bytes(xb);
            for (j, vj) in v.iter_mut().enumerate() {
                let val = F::Int::truncate(x >> (D::USIZE * j));
                vj.0 = val & mask;

                // Special case for FIPS 203
                if D::USIZE == 12 {
                    vj.0 = vj.0 % F::Q;
                }
            }
        }

        vals
    }

    pub trait Encode<D: EncodingSize> {
        type EncodedSize: ArraySize;
        fn encode(&self) -> Array<u8, Self::EncodedSize>;
        fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self;
    }

    impl<F: Field, D: EncodingSize> Encode<D> for Polynomial<F> {
        type EncodedSize = D::EncodedPolynomialSize;

        fn encode(&self) -> Array<u8, Self::EncodedSize> {
            byte_encode::<F, D>(&self.0)
        }

        fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
            Self(byte_decode::<F, D>(enc))
        }
    }

    impl<F, D, K> Encode<D> for Vector<F, K>
    where
        F: Field,
        K: ArraySize,
        D: VectorEncodingSize<K>,
    {
        type EncodedSize = D::EncodedVectorSize;

        fn encode(&self) -> Array<u8, Self::EncodedSize> {
            let polys = self.0.iter().map(|x| Encode::<D>::encode(x)).collect();
            <D as VectorEncodingSize<K>>::flatten(polys)
        }

        fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
            let unfold = <D as VectorEncodingSize<K>>::unflatten(enc);
            Self(
                unfold
                    .iter()
                    .map(|&x| <Polynomial<F> as Encode<D>>::decode(x))
                    .collect(),
            )
        }
    }

    impl<F: Field, D: EncodingSize> Encode<D> for NttPolynomial<F> {
        type EncodedSize = D::EncodedPolynomialSize;

        fn encode(&self) -> Array<u8, Self::EncodedSize> {
            byte_encode::<F, D>(&self.0)
        }

        fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
            Self(byte_decode::<F, D>(enc))
        }
    }

    impl<F, D, K> Encode<D> for NttVector<F, K>
    where
        F: Field,
        D: VectorEncodingSize<K>,
        K: ArraySize,
    {
        type EncodedSize = D::EncodedVectorSize;

        fn encode(&self) -> Array<u8, Self::EncodedSize> {
            let polys = self.0.iter().map(|x| Encode::<D>::encode(x)).collect();
            <D as VectorEncodingSize<K>>::flatten(polys)
        }

        fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
            let unfold = <D as VectorEncodingSize<K>>::unflatten(enc);
            Self(
                unfold
                    .iter()
                    .map(|&x| <NttPolynomial<F> as Encode<D>>::decode(x))
                    .collect(),
            )
        }
    }
}
