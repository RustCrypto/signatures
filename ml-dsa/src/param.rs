//! This module encapsulates all of the compile-time logic related to parameter-set dependent sizes
//! of objects.  `ParameterSet` captures the parameters in the form described by the ML-KEM
//! specification.  `EncodingSize`, `VectorEncodingSize`, and `CbdSamplingSize` are "upstream" of
//! `ParameterSet`; they provide basic logic about the size of encoded objects.
//!
//! While the primary purpose of these traits is to describe the sizes of objects, in order to
//! avoid leakage of complicated trait bounds, they also need to provide any logic that needs to
//! know any details about object sizes.  For example, `VectorEncodingSize::flatten` needs to know
//! that the size of an encoded vector is `K` times the size of an encoded polynomial.

use core::fmt::Debug;
use core::ops::{Add, Div, Mul, Rem, Sub};

use crate::module_lattice::encode::{
    ArraySize, Encode, EncodedPolynomialSize, EncodedVectorSize, EncodingSize,
};
use hybrid_array::{
    Array,
    typenum::{
        Diff, Len, Length, Prod, Shleft, Sum, U0, U1, U2, U4, U13, U23, U32, U64, U128, U320, U416,
        Unsigned,
    },
};

use crate::algebra::{Polynomial, Vector};
use crate::encode::{
    BitPack, RangeEncodedPolynomialSize, RangeEncodedVectorSize, RangeEncodingSize,
};
use crate::util::{B32, B64};

/// Some useful compile-time constants
pub(crate) type SpecQ = Sum<Diff<Shleft<U1, U23>, Shleft<U1, U13>>, U1>;
pub(crate) type SpecD = U13;
pub(crate) type QMinus1 = Diff<SpecQ, U1>;
pub(crate) type BitlenQMinusD = Diff<Length<SpecQ>, SpecD>;
pub(crate) type Pow2DMinus1 = Shleft<U1, Diff<SpecD, U1>>;
pub(crate) type Pow2DMinus1Minus1 = Diff<Pow2DMinus1, U1>;

/// An integer that describes a bit length to be used in sampling
#[expect(unreachable_pub)]
pub trait SamplingSize: ArraySize + Len {
    const ETA: Eta;
}

#[derive(Copy, Clone)]
pub(crate) enum Eta {
    Two,
    Four,
}

impl SamplingSize for U2 {
    const ETA: Eta = Eta::Two;
}

impl SamplingSize for U4 {
    const ETA: Eta = Eta::Four;
}

/// An integer that describes a mask sampling size
#[expect(unreachable_pub)]
pub trait MaskSamplingSize: Unsigned {
    type SampleSize: ArraySize;

    fn unpack(v: &Array<u8, Self::SampleSize>) -> Polynomial;
}

impl<G> MaskSamplingSize for G
where
    G: Unsigned + Sub<U1>,
    (Diff<G, U1>, G): RangeEncodingSize,
{
    type SampleSize = RangeEncodedPolynomialSize<Diff<G, U1>, G>;

    fn unpack(v: &Array<u8, Self::SampleSize>) -> Polynomial {
        BitPack::<Diff<G, U1>, G>::unpack(v)
    }
}

/// A `ParameterSet` captures the parameters that describe a particular instance of ML-DSA.  There
/// are three variants, corresponding to three different security levels.
pub trait ParameterSet {
    /// Number of rows in the A matrix
    type K: ArraySize;

    /// Number of columns in the A matrix
    type L: ArraySize;

    /// Private key range
    type Eta: SamplingSize;

    /// Error size bound for y
    type Gamma1: MaskSamplingSize;

    /// Low-order rounding range
    type Gamma2: Unsigned;

    /// Low-order rounding range (2 * gamma2 in terms of the spec)
    type TwoGamma2: Unsigned;

    /// Encoding width of the W1 polynomial, namely bitlen((q - 1) / (2 * gamma2) - 1)
    type W1Bits: EncodingSize;

    /// Collision strength of `c_tilde`, in bytes (lambda / 4 in the spec)
    type Lambda: ArraySize;

    /// Max number of true values in the hint
    type Omega: ArraySize;

    /// Number of nonzero values in the polynomial c
    const TAU: usize;

    /// Beta = Tau * Eta
    #[allow(clippy::as_conversions)]
    #[allow(clippy::cast_possible_truncation)]
    const BETA: u32 = (Self::TAU as u32) * Self::Eta::U32;
}

pub trait SigningKeyParams: ParameterSet {
    type S1Size: ArraySize;
    type S2Size: ArraySize;
    type T0Size: ArraySize;
    type SigningKeySize: ArraySize;

    fn encode_s1(s1: &Vector<Self::L>) -> EncodedS1<Self>;
    fn decode_s1(enc: &EncodedS1<Self>) -> Vector<Self::L>;

    fn encode_s2(s2: &Vector<Self::K>) -> EncodedS2<Self>;
    fn decode_s2(enc: &EncodedS2<Self>) -> Vector<Self::K>;

    fn encode_t0(t0: &Vector<Self::K>) -> EncodedT0<Self>;
    fn decode_t0(enc: &EncodedT0<Self>) -> Vector<Self::K>;

    fn concat_sk(
        rho: B32,
        K: B32,
        tr: B64,
        s1: EncodedS1<Self>,
        s2: EncodedS2<Self>,
        t0: EncodedT0<Self>,
    ) -> EncodedSigningKey<Self>;
    fn split_sk(
        enc: &EncodedSigningKey<Self>,
    ) -> (
        &B32,
        &B32,
        &B64,
        &EncodedS1<Self>,
        &EncodedS2<Self>,
        &EncodedT0<Self>,
    );
}

pub(crate) type EncodedS1<P> = Array<u8, <P as SigningKeyParams>::S1Size>;
pub(crate) type EncodedS2<P> = Array<u8, <P as SigningKeyParams>::S2Size>;
pub(crate) type EncodedT0<P> = Array<u8, <P as SigningKeyParams>::T0Size>;

pub(crate) type SigningKeySize<P> = <P as SigningKeyParams>::SigningKeySize;

/// A signing key encoded as a byte array
pub type EncodedSigningKey<P> = Array<u8, SigningKeySize<P>>;

impl<P> SigningKeyParams for P
where
    P: ParameterSet,
    // General rules about Eta
    P::Eta: Add<P::Eta>,
    Sum<P::Eta, P::Eta>: Len,
    Length<Sum<P::Eta, P::Eta>>: EncodingSize,
    // S1 encoding with Eta (L-size)
    EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>: Mul<P::L>,
    Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::L>: ArraySize
        + Div<P::L, Output = EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>>
        + Rem<P::L, Output = U0>,
    // S2 encoding with Eta (K-size)
    EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>: Mul<P::K>,
    Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::K>: ArraySize
        + Div<P::K, Output = EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>>
        + Rem<P::K, Output = U0>,
    // T0 encoding in -2^{d-1}-1 .. 2^{d-1} (D bits) (416 = 32 * D)
    U416: Mul<P::K>,
    Prod<U416, P::K>: ArraySize + Div<P::K, Output = U416> + Rem<P::K, Output = U0>,
    // Signing key encoding rules
    U128: Add<Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::L>>,
    Sum<U128, Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::L>>: ArraySize
        + Add<Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::K>>
        + Sub<U128, Output = Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::L>>,
    Sum<
        Sum<U128, Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::L>>,
        Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::K>,
    >: ArraySize
        + Add<Prod<U416, P::K>>
        + Sub<
            Sum<U128, Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::L>>,
            Output = Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::K>,
        >,
    Sum<
        Sum<
            Sum<U128, Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::L>>,
            Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::K>,
        >,
        Prod<U416, P::K>,
    >: ArraySize
        + Sub<
            Sum<
                Sum<U128, Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::L>>,
                Prod<EncodedPolynomialSize<Length<Sum<P::Eta, P::Eta>>>, P::K>,
            >,
            Output = Prod<U416, P::K>,
        >,
{
    type S1Size = RangeEncodedVectorSize<P::Eta, P::Eta, P::L>;
    type S2Size = RangeEncodedVectorSize<P::Eta, P::Eta, P::K>;
    type T0Size = RangeEncodedVectorSize<Pow2DMinus1Minus1, Pow2DMinus1, P::K>;
    type SigningKeySize = Sum<
        Sum<
            Sum<U128, RangeEncodedVectorSize<P::Eta, P::Eta, P::L>>,
            RangeEncodedVectorSize<P::Eta, P::Eta, P::K>,
        >,
        RangeEncodedVectorSize<Pow2DMinus1Minus1, Pow2DMinus1, P::K>,
    >;

    fn encode_s1(s1: &Vector<Self::L>) -> EncodedS1<Self> {
        BitPack::<P::Eta, P::Eta>::pack(s1)
    }

    fn decode_s1(enc: &EncodedS1<Self>) -> Vector<Self::L> {
        BitPack::<P::Eta, P::Eta>::unpack(enc)
    }

    fn encode_s2(s2: &Vector<Self::K>) -> EncodedS2<Self> {
        BitPack::<P::Eta, P::Eta>::pack(s2)
    }

    fn decode_s2(enc: &EncodedS2<Self>) -> Vector<Self::K> {
        BitPack::<P::Eta, P::Eta>::unpack(enc)
    }

    fn encode_t0(t0: &Vector<Self::K>) -> EncodedT0<Self> {
        BitPack::<Pow2DMinus1Minus1, Pow2DMinus1>::pack(t0)
    }

    fn decode_t0(enc: &EncodedT0<Self>) -> Vector<Self::K> {
        BitPack::<Pow2DMinus1Minus1, Pow2DMinus1>::unpack(enc)
    }

    fn concat_sk(
        rho: B32,
        K: B32,
        tr: B64,
        s1: EncodedS1<Self>,
        s2: EncodedS2<Self>,
        t0: EncodedT0<Self>,
    ) -> EncodedSigningKey<Self> {
        rho.concat(K).concat(tr).concat(s1).concat(s2).concat(t0)
    }

    fn split_sk(
        enc: &EncodedSigningKey<Self>,
    ) -> (
        &B32,
        &B32,
        &B64,
        &EncodedS1<Self>,
        &EncodedS2<Self>,
        &EncodedT0<Self>,
    ) {
        let (enc, t0) = enc.split_ref();
        let (enc, s2) = enc.split_ref();
        let (enc, s1) = enc.split_ref();
        let (enc, tr) = enc.split_ref::<U64>();
        let (rho, K) = enc.split_ref();
        (rho, K, tr, s1, s2, t0)
    }
}

pub trait VerifyingKeyParams: ParameterSet {
    type T1Size: ArraySize;
    type VerifyingKeySize: ArraySize;

    fn encode_t1(t1: &Vector<Self::K>) -> EncodedT1<Self>;
    fn decode_t1(enc: &EncodedT1<Self>) -> Vector<Self::K>;

    fn concat_vk(rho: B32, t1: EncodedT1<Self>) -> EncodedVerifyingKey<Self>;
    fn split_vk(enc: &EncodedVerifyingKey<Self>) -> (&B32, &EncodedT1<Self>);
}

pub(crate) type VerifyingKeySize<P> = <P as VerifyingKeyParams>::VerifyingKeySize;

pub(crate) type EncodedT1<P> = Array<u8, <P as VerifyingKeyParams>::T1Size>;

/// A verifying key encoded as a byte array
pub type EncodedVerifyingKey<P> = Array<u8, VerifyingKeySize<P>>;

impl<P> VerifyingKeyParams for P
where
    P: ParameterSet,
    // T1 encoding rules
    U320: Mul<P::K>,
    Prod<U320, P::K>: ArraySize + Div<P::K, Output = U320> + Rem<P::K, Output = U0>,
    // Verifying key encoding rules
    U32: Add<Prod<U320, P::K>>,
    Sum<U32, U32>: ArraySize,
    Sum<U32, Prod<U320, P::K>>: ArraySize + Sub<U32, Output = Prod<U320, P::K>>,
{
    type T1Size = EncodedVectorSize<BitlenQMinusD, P::K>;
    type VerifyingKeySize = Sum<U32, Self::T1Size>;

    fn encode_t1(t1: &Vector<P::K>) -> EncodedT1<Self> {
        Encode::<BitlenQMinusD>::encode(t1)
    }

    fn decode_t1(enc: &EncodedT1<Self>) -> Vector<Self::K> {
        Encode::<BitlenQMinusD>::decode(enc)
    }

    fn concat_vk(rho: B32, t1: EncodedT1<Self>) -> EncodedVerifyingKey<Self> {
        rho.concat(t1)
    }

    fn split_vk(enc: &EncodedVerifyingKey<Self>) -> (&B32, &EncodedT1<Self>) {
        enc.split_ref()
    }
}

pub trait SignatureParams: ParameterSet {
    type W1Size: ArraySize;
    type ZSize: ArraySize;
    type HintSize: ArraySize;
    type SignatureSize: ArraySize;

    const GAMMA1_MINUS_BETA: u32;
    const GAMMA2_MINUS_BETA: u32;

    fn split_hint(y: &EncodedHint<Self>) -> (&EncodedHintIndices<Self>, &EncodedHintCuts<Self>);

    fn encode_w1(t1: &Vector<Self::K>) -> EncodedW1<Self>;
    fn decode_w1(enc: &EncodedW1<Self>) -> Vector<Self::K>;

    fn encode_z(z: &Vector<Self::L>) -> EncodedZ<Self>;
    fn decode_z(enc: &EncodedZ<Self>) -> Vector<Self::L>;

    fn concat_sig(
        c_tilde: EncodedCTilde<Self>,
        z: EncodedZ<Self>,
        h: EncodedHint<Self>,
    ) -> EncodedSignature<Self>;
    fn split_sig(
        enc: &EncodedSignature<Self>,
    ) -> (&EncodedCTilde<Self>, &EncodedZ<Self>, &EncodedHint<Self>);
}

pub(crate) type SignatureSize<P> = <P as SignatureParams>::SignatureSize;

pub(crate) type EncodedCTilde<P> = Array<u8, <P as ParameterSet>::Lambda>;
pub(crate) type EncodedW1<P> = Array<u8, <P as SignatureParams>::W1Size>;
pub(crate) type EncodedZ<P> = Array<u8, <P as SignatureParams>::ZSize>;
pub(crate) type EncodedHintIndices<P> = Array<u8, <P as ParameterSet>::Omega>;
pub(crate) type EncodedHintCuts<P> = Array<u8, <P as ParameterSet>::K>;
pub(crate) type EncodedHint<P> = Array<u8, <P as SignatureParams>::HintSize>;

/// A signature encoded as a byte array
pub type EncodedSignature<P> = Array<u8, SignatureSize<P>>;

impl<P> SignatureParams for P
where
    P: ParameterSet,
    // W1
    U32: Mul<P::W1Bits>,
    EncodedPolynomialSize<P::W1Bits>: Mul<P::K>,
    Prod<EncodedPolynomialSize<P::W1Bits>, P::K>:
        ArraySize + Div<P::K, Output = EncodedPolynomialSize<P::W1Bits>> + Rem<P::K, Output = U0>,
    // Z
    P::Gamma1: Sub<U1>,
    (Diff<P::Gamma1, U1>, P::Gamma1): RangeEncodingSize,
    RangeEncodedPolynomialSize<Diff<P::Gamma1, U1>, P::Gamma1>: Mul<P::L>,
    Prod<RangeEncodedPolynomialSize<Diff<P::Gamma1, U1>, P::Gamma1>, P::L>: ArraySize
        + Div<P::L, Output = RangeEncodedPolynomialSize<Diff<P::Gamma1, U1>, P::Gamma1>>
        + Rem<P::L, Output = U0>,
    // Hint
    P::Omega: Add<P::K>,
    Sum<P::Omega, P::K>: ArraySize + Sub<P::Omega, Output = P::K>,
    // Signature
    P::Lambda: Add<Prod<RangeEncodedPolynomialSize<Diff<P::Gamma1, U1>, P::Gamma1>, P::L>>,
    Sum<P::Lambda, Prod<RangeEncodedPolynomialSize<Diff<P::Gamma1, U1>, P::Gamma1>, P::L>>:
        ArraySize
            + Add<Sum<P::Omega, P::K>>
            + Sub<
                P::Lambda,
                Output = Prod<RangeEncodedPolynomialSize<Diff<P::Gamma1, U1>, P::Gamma1>, P::L>,
            >,
    Sum<
        Sum<P::Lambda, Prod<RangeEncodedPolynomialSize<Diff<P::Gamma1, U1>, P::Gamma1>, P::L>>,
        Sum<P::Omega, P::K>,
    >: ArraySize
        + Sub<
            Sum<P::Lambda, Prod<RangeEncodedPolynomialSize<Diff<P::Gamma1, U1>, P::Gamma1>, P::L>>,
            Output = Sum<P::Omega, P::K>,
        >,
{
    type W1Size = EncodedVectorSize<Self::W1Bits, P::K>;
    type ZSize = RangeEncodedVectorSize<Diff<P::Gamma1, U1>, P::Gamma1, P::L>;
    type HintSize = Sum<P::Omega, P::K>;
    type SignatureSize = Sum<Sum<P::Lambda, Self::ZSize>, Self::HintSize>;

    const GAMMA1_MINUS_BETA: u32 = P::Gamma1::U32 - P::BETA;
    const GAMMA2_MINUS_BETA: u32 = P::Gamma2::U32 - P::BETA;

    fn split_hint(y: &EncodedHint<Self>) -> (&EncodedHintIndices<Self>, &EncodedHintCuts<Self>) {
        y.split_ref()
    }

    fn encode_w1(w1: &Vector<Self::K>) -> EncodedW1<Self> {
        Encode::<Self::W1Bits>::encode(w1)
    }

    fn decode_w1(enc: &EncodedW1<Self>) -> Vector<Self::K> {
        Encode::<Self::W1Bits>::decode(enc)
    }

    fn encode_z(z: &Vector<Self::L>) -> EncodedZ<Self> {
        BitPack::<Diff<P::Gamma1, U1>, P::Gamma1>::pack(z)
    }

    fn decode_z(enc: &EncodedZ<Self>) -> Vector<Self::L> {
        BitPack::<Diff<P::Gamma1, U1>, P::Gamma1>::unpack(enc)
    }

    fn concat_sig(
        c_tilde: EncodedCTilde<P>,
        z: EncodedZ<P>,
        h: EncodedHint<P>,
    ) -> EncodedSignature<P> {
        c_tilde.concat(z).concat(h)
    }

    fn split_sig(enc: &EncodedSignature<P>) -> (&EncodedCTilde<P>, &EncodedZ<P>, &EncodedHint<P>) {
        let (enc, h) = enc.split_ref();
        let (c_tilde, z) = enc.split_ref();
        (c_tilde, z, h)
    }
}

/// An instance of `MlDsaParams` defines all of the parameters necessary for ML-DSA operations.
/// Typically this is done by implementing `ParameterSet` with values that will fit into the
/// blanket implementations of `SigningKeyParams`, `VerifyingKeyParams`, and `SignatureParams`.
pub trait MlDsaParams:
    SigningKeyParams + VerifyingKeyParams + SignatureParams + Debug + Default + PartialEq + Clone
{
}

impl<T> MlDsaParams for T where
    T: SigningKeyParams
        + VerifyingKeyParams
        + SignatureParams
        + Debug
        + Default
        + PartialEq
        + Clone
{
}
