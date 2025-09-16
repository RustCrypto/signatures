use core::fmt::Debug;
use core::ops::{Div, Mul, Rem};
use hybrid_array::{
    Array,
    typenum::{Gcd, Gcf, Prod, Quot, U0, U8, U32, U256, Unsigned},
};
use num_traits::One;

use super::algebra::{Elem, Field, NttPolynomial, NttVector, Polynomial, Vector};
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

pub(crate) type EncodedPolynomialSize<D> = <D as EncodingSize>::EncodedPolynomialSize;
pub(crate) type EncodedPolynomial<D> = Array<u8, EncodedPolynomialSize<D>>;

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

pub(crate) type EncodedVectorSize<D, K> = <D as VectorEncodingSize<K>>::EncodedVectorSize;
pub(crate) type EncodedVector<D, K> = Array<u8, EncodedVectorSize<D, K>>;

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

pub(crate) trait Encode<D: EncodingSize> {
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
