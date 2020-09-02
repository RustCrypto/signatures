//! Minimalist example curve implementation for testing.
//!
//! Modeled after NIST P-256.

use core::{convert::TryInto, ops::Mul};
use elliptic_curve::{
    consts::U32,
    digest::Digest,
    ops::Invert,
    point::Generator,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    util::{adc64, sbb64},
    zeroize::Zeroize,
    FromBytes, FromDigest,
};

/// Example NIST P-256-like elliptic curve.
/// Implements only the features needed for testing the implementation.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct ExampleCurve;

impl elliptic_curve::Curve for ExampleCurve {
    type ElementSize = U32;
}

impl elliptic_curve::weierstrass::Curve for ExampleCurve {
    const COMPRESS_POINTS: bool = false;
}

impl elliptic_curve::Arithmetic for ExampleCurve {
    type Scalar = Scalar;
    type AffinePoint = AffinePoint;
}

const LIMBS: usize = 4;

type U256 = [u64; LIMBS];

const MODULUS: U256 = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

/// Example scalar type
#[derive(Clone, Copy, Debug, Default)]
pub struct Scalar([u64; LIMBS]);

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl FromBytes for Scalar {
    type Size = U32;

    fn from_bytes(bytes: &ElementBytes) -> CtOption<Self> {
        let mut w = [0u64; LIMBS];

        // Interpret the bytes as a big-endian integer w.
        w[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());

        // If w is in the range [0, n) then w - n will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb64(w[0], MODULUS[0], 0);
        let (_, borrow) = sbb64(w[1], MODULUS[1], borrow);
        let (_, borrow) = sbb64(w[2], MODULUS[2], borrow);
        let (_, borrow) = sbb64(w[3], MODULUS[3], borrow);
        let is_some = (borrow as u8) & 1;

        CtOption::new(Scalar(w), Choice::from(is_some))
    }
}

impl From<Scalar> for ElementBytes {
    fn from(scalar: Scalar) -> Self {
        let mut ret = ElementBytes::default();
        ret[0..8].copy_from_slice(&scalar.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&scalar.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&scalar.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&scalar.0[0].to_be_bytes());
        ret
    }
}

impl FromDigest<ExampleCurve> for Scalar {
    fn from_digest<D>(digest: D) -> Self
    where
        D: Digest<OutputSize = U32>,
    {
        let bytes = digest.finalize();

        Self::sub_inner(
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            0,
            MODULUS[0],
            MODULUS[1],
            MODULUS[2],
            MODULUS[3],
            0,
        )
    }
}

impl Invert for Scalar {
    type Output = Self;

    fn invert(&self) -> CtOption<Self> {
        unimplemented!();
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize()
    }
}

impl Scalar {
    #[allow(clippy::too_many_arguments)]
    const fn sub_inner(
        l0: u64,
        l1: u64,
        l2: u64,
        l3: u64,
        l4: u64,
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
    ) -> Self {
        let (w0, borrow) = sbb64(l0, r0, 0);
        let (w1, borrow) = sbb64(l1, r1, borrow);
        let (w2, borrow) = sbb64(l2, r2, borrow);
        let (w3, borrow) = sbb64(l3, r3, borrow);
        let (_, borrow) = sbb64(l4, r4, borrow);

        let (w0, carry) = adc64(w0, MODULUS[0] & borrow, 0);
        let (w1, carry) = adc64(w1, MODULUS[1] & borrow, carry);
        let (w2, carry) = adc64(w2, MODULUS[2] & borrow, carry);
        let (w3, _) = adc64(w3, MODULUS[3] & borrow, carry);

        Scalar([w0, w1, w2, w3])
    }
}

/// Field element bytes;
pub type ElementBytes = elliptic_curve::ElementBytes<ExampleCurve>;

/// Non-zero scalar value.
pub type NonZeroScalar = elliptic_curve::scalar::NonZeroScalar<ExampleCurve>;

/// Example affine point type
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(_a: &Self, _b: &Self, _choice: Choice) -> Self {
        unimplemented!();
    }
}

impl Mul<NonZeroScalar> for AffinePoint {
    type Output = AffinePoint;

    fn mul(self, _scalar: NonZeroScalar) -> Self {
        unimplemented!();
    }
}

impl Generator for AffinePoint {
    fn generator() -> AffinePoint {
        unimplemented!();
    }
}
