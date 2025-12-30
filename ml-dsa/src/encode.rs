use crate::module_lattice::encode::{ArraySize, Encode, EncodingSize, VectorEncodingSize};
use core::ops::Add;
use hybrid_array::{
    Array,
    typenum::{Len, Length, Sum, Unsigned},
};

use crate::algebra::{Elem, Polynomial, Vector};

/// A pair of integers that describes a range
pub trait RangeEncodingSize {
    type Min: Unsigned;
    type Max: Unsigned;
    type EncodingSize: EncodingSize;
}

impl<A, B> RangeEncodingSize for (A, B)
where
    A: Unsigned + Add<B>,
    B: Unsigned,
    Sum<A, B>: Len,
    Length<Sum<A, B>>: EncodingSize,
{
    type Min = A;
    type Max = B;
    type EncodingSize = Length<Sum<A, B>>;
}

pub(crate) type RangeMin<A, B> = <(A, B) as RangeEncodingSize>::Min;
pub(crate) type RangeMax<A, B> = <(A, B) as RangeEncodingSize>::Max;
pub(crate) type RangeEncodingBits<A, B> = <(A, B) as RangeEncodingSize>::EncodingSize;
pub(crate) type RangeEncodedPolynomialSize<A, B> =
    <RangeEncodingBits<A, B> as EncodingSize>::EncodedPolynomialSize;
pub(crate) type RangeEncodedPolynomial<A, B> = Array<u8, RangeEncodedPolynomialSize<A, B>>;
pub(crate) type RangeEncodedVectorSize<A, B, K> =
    <RangeEncodingBits<A, B> as VectorEncodingSize<K>>::EncodedVectorSize;
pub(crate) type RangeEncodedVector<A, B, K> = Array<u8, RangeEncodedVectorSize<A, B, K>>;

/// `BitPack` represents range-encoding logic
pub(crate) trait BitPack<A, B> {
    type PackedSize: ArraySize;
    fn pack(&self) -> Array<u8, Self::PackedSize>;
    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self;
}

impl<A, B> BitPack<A, B> for Polynomial
where
    (A, B): RangeEncodingSize,
{
    type PackedSize = RangeEncodedPolynomialSize<A, B>;

    // Algorithm 17 BitPack
    fn pack(&self) -> RangeEncodedPolynomial<A, B> {
        let a = Elem::new(RangeMin::<A, B>::U32);
        let b = Elem::new(RangeMax::<A, B>::U32);

        let to_encode = Self::new(
            self.0
                .iter()
                .map(|w| {
                    assert!(w.0 <= b.0 || w.0 >= (-a).0);
                    b - *w
                })
                .collect(),
        );
        Encode::<RangeEncodingBits<A, B>>::encode(&to_encode)
    }

    // Algorithm 17 BitUnPack
    fn unpack(enc: &RangeEncodedPolynomial<A, B>) -> Self {
        let a = Elem::new(RangeMin::<A, B>::U32);
        let b = Elem::new(RangeMax::<A, B>::U32);
        let mut decoded: Self = Encode::<RangeEncodingBits<A, B>>::decode(enc);

        for z in &mut decoded.0 {
            assert!(z.0 <= (a + b).0);
            *z = b - *z;
        }

        decoded
    }
}

impl<K, A, B> BitPack<A, B> for Vector<K>
where
    K: ArraySize,
    (A, B): RangeEncodingSize,
    RangeEncodingBits<A, B>: VectorEncodingSize<K>,
{
    type PackedSize = RangeEncodedVectorSize<A, B, K>;

    fn pack(&self) -> RangeEncodedVector<A, B, K> {
        let polys = self.0.iter().map(|x| BitPack::<A, B>::pack(x)).collect();
        RangeEncodingBits::<A, B>::flatten(polys)
    }

    fn unpack(enc: &RangeEncodedVector<A, B, K>) -> Self {
        let unfold = RangeEncodingBits::<A, B>::unflatten(enc);
        Self(
            unfold
                .into_iter()
                .map(|x| <Polynomial as BitPack<A, B>>::unpack(x))
                .collect(),
        )
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{algebra::*, module_lattice::encode::*};
    use core::ops::Rem;
    use getrandom::rand_core::{RngCore, TryRngCore};
    use hybrid_array::typenum::{
        U1, U2, U3, U4, U6, U7, U8, U9, U10, U13, U17, U19,
        marker_traits::Zero,
        operator_aliases::{Diff, Mod, Shleft},
    };

    // A helper trait to construct larger arrays by repeating smaller ones
    trait Repeat<T: Clone, D: ArraySize> {
        fn repeat(&self) -> Array<T, D>;
    }

    impl<T, N, D> Repeat<T, D> for Array<T, N>
    where
        N: ArraySize,
        T: Clone,
        D: ArraySize + Rem<N>,
        Mod<D, N>: Zero,
    {
        #[allow(clippy::integer_division_remainder_used)]
        fn repeat(&self) -> Array<T, D> {
            Array::from_fn(|i| self[i % N::USIZE].clone())
        }
    }

    #[allow(clippy::integer_division_remainder_used)]
    fn simple_bit_pack_test<D>(b: u32, decoded: &Polynomial, encoded: &EncodedPolynomial<D>)
    where
        D: EncodingSize,
    {
        // Test known answer
        let actual_encoded = Encode::<D>::encode(decoded);
        assert_eq!(actual_encoded, *encoded);

        let actual_decoded: Polynomial = Encode::<D>::decode(encoded);
        assert_eq!(actual_decoded, *decoded);

        // Test random decode/encode and encode/decode round trips
        let mut rng = getrandom::SysRng.unwrap_err();
        let decoded = Polynomial::new(Array::from_fn(|_| {
            let x = rng.next_u32();
            Elem::new(x % (b + 1))
        }));

        let actual_encoded = Encode::<D>::encode(&decoded);
        let actual_decoded: Polynomial = Encode::<D>::decode(&actual_encoded);
        assert_eq!(actual_decoded, decoded);

        let actual_reencoded = Encode::<D>::encode(&decoded);
        assert_eq!(actual_reencoded, actual_encoded);
    }

    #[test]
    fn simple_bit_pack() {
        // Use a standard test pattern across all the cases
        let decoded = Polynomial::new(
            Array::<_, U8>([
                Elem::new(0),
                Elem::new(1),
                Elem::new(2),
                Elem::new(3),
                Elem::new(4),
                Elem::new(5),
                Elem::new(6),
                Elem::new(7),
            ])
            .repeat(),
        );

        // 10 bits
        // <-> b = 2^{bitlen(q-1) - d} - 1 = 2^10 - 1
        let b = (1 << 10) - 1;
        let encoded: EncodedPolynomial<U10> =
            Array::<_, U10>([0x00, 0x04, 0x20, 0xc0, 0x00, 0x04, 0x14, 0x60, 0xc0, 0x01]).repeat();
        simple_bit_pack_test::<U10>(b, &decoded, &encoded);

        // 8 bits
        // gamma2 = (q - 1) / 88
        // b = (q - 1) / (2 gamma2) - 1 = 175 = 2^8 - 81
        let b = (1 << 8) - 81;
        let encoded: EncodedPolynomial<U8> =
            Array::<_, U8>([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]).repeat();
        simple_bit_pack_test::<U8>(b, &decoded, &encoded);

        // 6 bits
        // gamma2 = (q - 1) / 32
        // b = (q - 1) / (2 gamma2) - 1 = 63 = 2^6 - 1
        let b = (1 << 6) - 1;
        let encoded: EncodedPolynomial<U6> =
            Array::<_, U6>([0x40, 0x20, 0x0c, 0x44, 0x61, 0x1c]).repeat();
        simple_bit_pack_test::<U6>(b, &decoded, &encoded);
    }

    #[allow(clippy::integer_division_remainder_used)]
    fn bit_pack_test<A, B>(decoded: &Polynomial, encoded: &RangeEncodedPolynomial<A, B>)
    where
        A: Unsigned,
        B: Unsigned,
        (A, B): RangeEncodingSize,
    {
        let a = Elem::new(A::U32);
        let b = Elem::new(B::U32);

        // Test known answer
        let actual_encoded = BitPack::<A, B>::pack(decoded);
        assert_eq!(actual_encoded, *encoded);

        let actual_decoded: Polynomial = BitPack::<A, B>::unpack(encoded);
        assert_eq!(actual_decoded, *decoded);

        // Test random decode/encode and encode/decode round trips
        let mut rng = getrandom::SysRng.unwrap_err();
        let decoded = Polynomial::new(Array::from_fn(|_| {
            let mut x = rng.next_u32();
            x %= a.0 + b.0;
            b - Elem::new(x)
        }));

        let actual_encoded = BitPack::<A, B>::pack(&decoded);
        let actual_decoded: Polynomial = BitPack::<A, B>::unpack(&actual_encoded);
        assert_eq!(actual_decoded, decoded);

        let actual_reencoded = BitPack::<A, B>::pack(&decoded);
        assert_eq!(actual_reencoded, actual_encoded);
    }

    #[test]
    fn bit_pack() {
        type D = U13;
        type Pow2D = Shleft<U1, D>;
        type Pow2DMin = Diff<Pow2D, U1>;

        type Gamma1Lo = Shleft<U1, U17>;
        type Gamma1LoMin = Diff<Gamma1Lo, U1>;

        type Gamma1Hi = Shleft<U1, U19>;
        type Gamma1HiMin = Diff<Gamma1Hi, U1>;

        // Use a standard test pattern across all the cases
        // (We can't use -2 because the eta=2 case doesn't actually cover -2)
        let decoded = Polynomial::new(
            Array::<_, U4>([
                Elem::new(BaseField::Q - 1),
                Elem::new(0),
                Elem::new(1),
                Elem::new(2),
            ])
            .repeat(),
        );

        // BitPack(_, eta, eta), eta = 2, 4
        let encoded: RangeEncodedPolynomial<U2, U2> = Array::<_, U3>([0x53, 0x30, 0x05]).repeat();
        bit_pack_test::<U2, U2>(&decoded, &encoded);

        let encoded: RangeEncodedPolynomial<U4, U4> = Array::<_, U2>([0x45, 0x23]).repeat();
        bit_pack_test::<U4, U4>(&decoded, &encoded);

        // BitPack(_, 2^d - 1, 2^d), d = 13
        let encoded: RangeEncodedPolynomial<Pow2DMin, Pow2D> =
            Array::<_, U7>([0x01, 0x20, 0x00, 0xf8, 0xff, 0xf9, 0x7f]).repeat();
        bit_pack_test::<Pow2DMin, Pow2D>(&decoded, &encoded);

        // BitPack(_, gamma1 - 1, gamma1), gamma1 = 2^17, 2^19
        let encoded: RangeEncodedPolynomial<Gamma1LoMin, Gamma1Lo> =
            Array::<_, U9>([0x01, 0x00, 0x02, 0x00, 0xf8, 0xff, 0x9f, 0xff, 0x7f]).repeat();
        bit_pack_test::<Gamma1LoMin, Gamma1Lo>(&decoded, &encoded);

        let encoded: RangeEncodedPolynomial<Gamma1HiMin, Gamma1Hi> =
            Array::<_, U10>([0x00, 0x00, 0xf8, 0xff, 0x7f, 0xfe, 0xff, 0xd7, 0xff, 0x7f]).repeat();
        bit_pack_test::<Gamma1Hi, Gamma1HiMin>(&decoded, &encoded);
    }
}
