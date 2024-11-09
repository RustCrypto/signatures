use hybrid_array::{typenum::*, Array};

use crate::algebra::*;
use crate::param::*;

pub type DecodedValue<T> = Array<T, U256>;

// Algorithm 16 SimpleBitPack
fn simple_bit_pack<D, T>(vals: &DecodedValue<T>) -> EncodedPolynomial<D>
where
    D: EncodingSize,
    T: Copy,
    u128: From<T>,
{
    let val_step = D::ValueStep::USIZE;
    let byte_step = D::ByteStep::USIZE;

    let mut bytes = EncodedPolynomial::<D>::default();

    let vc = vals.chunks(val_step);
    let bc = bytes.chunks_mut(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut x = 0u128;
        for (j, vj) in v.iter().enumerate() {
            x |= u128::from(*vj) << (D::USIZE * j);
        }

        let xb = x.to_le_bytes();
        b.copy_from_slice(&xb[..byte_step]);
    }

    bytes
}

// Algorithm 18 SimpleBitUnpack
fn simple_bit_unpack<D, T>(bytes: &EncodedPolynomial<D>) -> DecodedValue<T>
where
    D: EncodingSize,
    T: From<u128> + Default,
{
    let val_step = D::ValueStep::USIZE;
    let byte_step = D::ByteStep::USIZE;
    let mask = (1 << D::USIZE) - 1;

    let mut vals = DecodedValue::<T>::default();

    let vc = vals.chunks_mut(val_step);
    let bc = bytes.chunks(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut xb = [0u8; 16];
        xb[..byte_step].copy_from_slice(b);

        let x = u128::from_le_bytes(xb);
        for (j, vj) in v.iter_mut().enumerate() {
            let val: u128 = (x >> (D::USIZE * j)) & mask;
            *vj = T::from(val);
        }
    }

    vals
}

// Algorithm 17 BitPack
fn bit_pack<A, B>(vals: &DecodedValue<FieldElement>) -> RangeEncodedPolynomial<A, B>
where
    (A, B): RangeEncodingSize,
{
    let a = FieldElement(RangeMin::<A, B>::U32);
    let b = FieldElement(RangeMax::<A, B>::U32);
    let to_encode = vals
        .iter()
        .map(|w| {
            assert!(w.0 <= b.0 || w.0 >= (-a).0);
            b - *w
        })
        .collect();
    simple_bit_pack::<RangeEncodingBits<A, B>, FieldElement>(&to_encode)
}

// FAlgorithm 17 BitPack
fn bit_unpack<A, B>(bytes: &RangeEncodedPolynomial<A, B>) -> DecodedValue<FieldElement>
where
    (A, B): RangeEncodingSize,
{
    let a = FieldElement(RangeMin::<A, B>::U32);
    let b = FieldElement(RangeMax::<A, B>::U32);
    let decoded = simple_bit_unpack::<RangeEncodingBits<A, B>, FieldElement>(bytes);
    decoded
        .iter()
        .map(|z| {
            assert!(z.0 < (a + b).0);
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
        simple_bit_pack::<D, FieldElement>(&self.0)
    }

    fn unpack(enc: &Array<u8, Self::PackedSize>) -> Self {
        Self(simple_bit_unpack::<D, FieldElement>(enc))
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
