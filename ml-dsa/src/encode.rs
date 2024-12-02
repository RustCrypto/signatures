use hybrid_array::{typenum::*, Array};

use crate::algebra::*;
use crate::param::*;
use crate::util::Truncate;

pub type DecodedValue = Array<FieldElement, U256>;

// Algorithm 16 SimpleBitPack
fn simple_bit_pack<D>(vals: &DecodedValue) -> EncodedPolynomial<D>
where
    D: EncodingSize,
{
    let val_step = D::ValueStep::USIZE;
    let byte_step = D::ByteStep::USIZE;

    let mut bytes = EncodedPolynomial::<D>::default();

    let vc = vals.chunks(val_step);
    let bc = bytes.chunks_mut(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut x = 0u128;
        for (j, vj) in v.iter().enumerate() {
            x |= u128::from(vj.0) << (D::USIZE * j);
        }

        let xb = x.to_le_bytes();
        b.copy_from_slice(&xb[..byte_step]);
    }

    bytes
}

// Algorithm 18 SimpleBitUnpack
fn simple_bit_unpack<D>(bytes: &EncodedPolynomial<D>) -> DecodedValue
where
    D: EncodingSize,
{
    let val_step = D::ValueStep::USIZE;
    let byte_step = D::ByteStep::USIZE;
    let mask = (1 << D::USIZE) - 1;

    let mut vals = DecodedValue::default();

    let vc = vals.chunks_mut(val_step);
    let bc = bytes.chunks(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut xb = [0u8; 16];
        xb[..byte_step].copy_from_slice(b);

        let x = u128::from_le_bytes(xb);
        for (j, vj) in v.iter_mut().enumerate() {
            let val: u128 = (x >> (D::USIZE * j)) & mask;
            *vj = FieldElement::new(val.truncate());
        }
    }

    vals
}

// Algorithm 17 BitPack
fn bit_pack<A, B>(vals: &DecodedValue) -> RangeEncodedPolynomial<A, B>
where
    (A, B): RangeEncodingSize,
{
    let a = FieldElement::new(RangeMin::<A, B>::U32);
    let b = FieldElement::new(RangeMax::<A, B>::U32);
    let to_encode = vals
        .iter()
        .map(|w| {
            assert!(w.0 <= b.0 || w.0 >= (-a).0);
            b - *w
        })
        .collect();
    simple_bit_pack::<RangeEncodingBits<A, B>>(&to_encode)
}

// Algorithm 17 BitPack
fn bit_unpack<A, B>(bytes: &RangeEncodedPolynomial<A, B>) -> DecodedValue
where
    (A, B): RangeEncodingSize,
{
    let a = FieldElement::new(RangeMin::<A, B>::U32);
    let b = FieldElement::new(RangeMax::<A, B>::U32);
    let decoded = simple_bit_unpack::<RangeEncodingBits<A, B>>(bytes);
    decoded
        .iter()
        .map(|z| {
            assert!(z.0 <= (a + b).0);
            b - *z
        })
        .collect()
}

/// SimpleBitPack
pub trait SimpleBitPack<D> {
    type PackedSize: ArraySize;
    fn pack(&self) -> Array<u8, Self::PackedSize>;
    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self;
}

impl<D> SimpleBitPack<D> for Polynomial
where
    D: EncodingSize,
{
    type PackedSize = D::EncodedPolynomialSize;

    fn pack(&self) -> Array<u8, Self::PackedSize> {
        simple_bit_pack::<D>(&self.0)
    }

    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self {
        Self(simple_bit_unpack::<D>(enc))
    }
}

impl<K, D> SimpleBitPack<D> for PolynomialVector<K>
where
    K: ArraySize,
    D: VectorEncodingSize<K>,
{
    type PackedSize = D::EncodedPolynomialVectorSize;

    fn pack(&self) -> Array<u8, Self::PackedSize> {
        let polys = self.0.iter().map(|x| SimpleBitPack::<D>::pack(x)).collect();
        D::flatten(polys)
    }

    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self {
        let unfold = D::unflatten(enc);
        Self(
            unfold
                .into_iter()
                .map(|x| <Polynomial as SimpleBitPack<D>>::unpack(x))
                .collect(),
        )
    }
}

/// BitPack
pub trait BitPack<A, B> {
    type PackedSize: ArraySize;
    fn pack(&self) -> Array<u8, Self::PackedSize>;
    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self;
}

impl<A, B> BitPack<A, B> for Polynomial
where
    (A, B): RangeEncodingSize,
{
    type PackedSize = EncodedPolynomialSize<RangeEncodingBits<A, B>>;

    fn pack(&self) -> Array<u8, Self::PackedSize> {
        bit_pack::<A, B>(&self.0)
    }

    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self {
        Self(bit_unpack::<A, B>(enc))
    }
}

impl<K, A, B> BitPack<A, B> for PolynomialVector<K>
where
    K: ArraySize,
    (A, B): RangeEncodingSize,
    RangeEncodingBits<A, B>: VectorEncodingSize<K>,
{
    type PackedSize = EncodedPolynomialVectorSize<RangeEncodingBits<A, B>, K>;

    fn pack(&self) -> Array<u8, Self::PackedSize> {
        let polys = self.0.iter().map(|x| BitPack::<A, B>::pack(x)).collect();
        RangeEncodingBits::<A, B>::flatten(polys)
    }

    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self {
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
    use core::ops::Rem;
    use hybrid_array::typenum::{
        marker_traits::Zero, operator_aliases::Mod, U1, U10, U2, U3, U4, U6, U8,
    };
    use rand::Rng;

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
        let actual_encoded = SimpleBitPack::<D>::pack(decoded);
        assert_eq!(actual_encoded, *encoded);

        let actual_decoded: Polynomial = SimpleBitPack::<D>::unpack(encoded);
        assert_eq!(actual_decoded, *decoded);

        // Test random decode/encode and encode/decode round trips
        let mut rng = rand::thread_rng();
        let decoded = Polynomial::new(Array::from_fn(|_| {
            let x: u32 = rng.gen();
            FieldElement::new(x % (b + 1))
        }));

        let actual_encoded = SimpleBitPack::<D>::pack(&decoded);
        let actual_decoded: Polynomial = SimpleBitPack::<D>::unpack(&actual_encoded);
        assert_eq!(actual_decoded, decoded);

        let actual_reencoded = SimpleBitPack::<D>::pack(&decoded);
        assert_eq!(actual_reencoded, actual_encoded);
    }

    #[test]
    fn simple_bit_pack() {
        // Use a standard test pattern across all the cases
        let decoded = Polynomial::new(
            Array::<_, U8>([
                FieldElement::new(0),
                FieldElement::new(1),
                FieldElement::new(2),
                FieldElement::new(3),
                FieldElement::new(4),
                FieldElement::new(5),
                FieldElement::new(6),
                FieldElement::new(7),
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
        let a = FieldElement::new(A::U32);
        let b = FieldElement::new(B::U32);

        // Test known answer
        let actual_encoded = BitPack::<A, B>::pack(decoded);
        assert_eq!(actual_encoded, *encoded);

        let actual_decoded: Polynomial = BitPack::<A, B>::unpack(encoded);
        assert_eq!(actual_decoded, *decoded);

        // Test random decode/encode and encode/decode round trips
        let mut rng = rand::thread_rng();
        let decoded = Polynomial::new(Array::from_fn(|_| {
            let mut x: u32 = rng.gen();
            x = x % (a.0 + b.0);
            b - FieldElement::new(x)
        }));

        let actual_encoded = BitPack::<A, B>::pack(&decoded);
        let actual_decoded: Polynomial = BitPack::<A, B>::unpack(&actual_encoded);
        assert_eq!(actual_decoded, decoded);

        let actual_reencoded = BitPack::<A, B>::pack(&decoded);
        assert_eq!(actual_reencoded, actual_encoded);
    }

    #[test]
    fn bit_pack() {
        // Use a standard test pattern across all the cases
        // (We can't use -2 because the eta=2 case doesn't actually cover -2)
        let decoded = Polynomial::new(
            Array::<_, U4>([
                FieldElement::new(BaseField::Q - 1),
                FieldElement::new(0),
                FieldElement::new(1),
                FieldElement::new(2),
            ])
            .repeat(),
        );

        // BitPack(_, eta, eta), eta = 2, 4
        let encoded: RangeEncodedPolynomial<U2, U2> = Array::<_, U3>([0x53, 0x30, 0x05]).repeat();
        bit_pack_test::<U2, U2>(&decoded, &encoded);

        let encoded: RangeEncodedPolynomial<U4, U4> = Array::<_, U2>([0x45, 0x23]).repeat();
        bit_pack_test::<U4, U4>(&decoded, &encoded);

        // BitPack(_, 2^d - 1, 2^d), d = 13
        type D = U13;
        type Pow2D = Shleft<U1, D>;
        type Pow2DMin = Diff<Pow2D, U1>;
        let encoded: RangeEncodedPolynomial<Pow2DMin, Pow2D> =
            Array::<_, U7>([0x01, 0x20, 0x00, 0xf8, 0xff, 0xf9, 0x7f]).repeat();
        bit_pack_test::<Pow2DMin, Pow2D>(&decoded, &encoded);

        // BitPack(_, gamma1 - 1, gamma1), gamma1 = 2^17, 2^19
        type Gamma1Lo = Shleft<U1, U17>;
        type Gamma1LoMin = Diff<Gamma1Lo, U1>;
        let encoded: RangeEncodedPolynomial<Gamma1LoMin, Gamma1Lo> =
            Array::<_, U9>([0x01, 0x00, 0x02, 0x00, 0xf8, 0xff, 0x9f, 0xff, 0x7f]).repeat();
        bit_pack_test::<Gamma1LoMin, Gamma1Lo>(&decoded, &encoded);

        type Gamma1Hi = Shleft<U1, U19>;
        type Gamma1HiMin = Diff<Gamma1Hi, U1>;
        let encoded: RangeEncodedPolynomial<Gamma1HiMin, Gamma1Hi> =
            Array::<_, U10>([0x00, 0x00, 0xf8, 0xff, 0x7f, 0xfe, 0xff, 0xd7, 0xff, 0x7f]).repeat();
        bit_pack_test::<Gamma1Hi, Gamma1HiMin>(&decoded, &encoded);
    }
}
