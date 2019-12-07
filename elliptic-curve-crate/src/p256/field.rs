//! Field arithmetic modulo p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1

use subtle::{Choice, ConstantTimeEq};

use super::util::{adc, sbb};

/// Constant representing the modulus
/// p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1
pub const MODULUS: FieldElement = FieldElement([
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);

/// An element in the finite field modulo p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1.
// The internal representation is in little-endian order.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement([u64; 4]);

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl FieldElement {
    /// Returns the zero element.
    pub const fn zero() -> FieldElement {
        FieldElement([0, 0, 0, 0])
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> FieldElement {
        FieldElement([1, 0, 0, 0])
    }

    /// Returns self + rhs mod p
    pub const fn add(&self, rhs: &Self) -> Self {
        // Bit 256 of p is set, so addition can result in five words.
        let (w0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (w1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (w2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (w3, w4) = adc(self.0[3], rhs.0[3], carry);

        // Attempt to subtract the modulus, to ensure the result is in the field.
        Self::sub_inner(
            w0,
            w1,
            w2,
            w3,
            w4,
            MODULUS.0[0],
            MODULUS.0[1],
            MODULUS.0[2],
            MODULUS.0[3],
            0,
        )
    }

    /// Returns self - rhs mod p
    pub const fn sub(&self, rhs: &Self) -> Self {
        Self::sub_inner(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
            0,
        )
    }

    #[inline]
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
        let (w0, borrow) = sbb(l0, r0, 0);
        let (w1, borrow) = sbb(l1, r1, borrow);
        let (w2, borrow) = sbb(l2, r2, borrow);
        let (w3, borrow) = sbb(l3, r3, borrow);
        let (_, borrow) = sbb(l4, r4, borrow);

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
        // modulus.
        let (w0, carry) = adc(w0, MODULUS.0[0] & borrow, 0);
        let (w1, carry) = adc(w1, MODULUS.0[1] & borrow, carry);
        let (w2, carry) = adc(w2, MODULUS.0[2] & borrow, carry);
        let (w3, _) = adc(w3, MODULUS.0[3] & borrow, carry);

        FieldElement([w0, w1, w2, w3])
    }
}

#[cfg(test)]
mod tests {
    use proptest::{num::u64::ANY, prelude::*};

    use super::FieldElement;

    #[test]
    fn zero_is_additive_identity() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        assert_eq!(zero.add(&zero), zero);
        assert_eq!(one.add(&zero), one);
    }

    proptest! {
        /// This checks behaviour well within the field ranges, because it doesn't set the
        /// highest limb.
        #[test]
        fn add_then_sub(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let a = FieldElement([a0, a1, a2, 0]);
            let b = FieldElement([b0, b1, b2, 0]);
            assert_eq!(a.add(&b).sub(&a), b);
        }
    }
}
