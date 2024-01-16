//! Constant-time comparison helpers for [`ByteArray`].

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time test that a given byte slice contains only zeroes.
#[inline]
pub(crate) fn ct_is_zero(n: &[u8]) -> Choice {
    let mut ret = Choice::from(1);

    for byte in n {
        ret.conditional_assign(&Choice::from(0), byte.ct_ne(&0));
    }

    ret
}

/// Constant-time less than.
///
/// Inputs are interpreted as big endian integers.
#[inline]
pub(crate) fn ct_lt(a: &[u8], b: &[u8]) -> Choice {
    debug_assert_eq!(a.len(), b.len());

    let mut borrow = 0;

    // Perform subtraction with borrow a byte-at-a-time, interpreting a
    // no-borrow condition as the less-than case
    for (&a, &b) in a.iter().zip(b.iter()).rev() {
        let c = (b as u16).wrapping_add(borrow >> (u8::BITS - 1));
        borrow = (a as u16).wrapping_sub(c) >> u8::BITS as u8;
    }

    !borrow.ct_eq(&0)
}

#[cfg(test)]
mod tests {
    const A: [u8; 4] = [0, 0, 0, 0];
    const B: [u8; 4] = [0, 0, 0, 1];
    const C: [u8; 4] = [0xFF, 0, 0, 0];
    const D: [u8; 4] = [0xFF, 0, 0, 1];
    const E: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFE];
    const F: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

    #[test]
    fn ct_is_zero() {
        use super::ct_is_zero;
        assert_eq!(ct_is_zero(&A).unwrap_u8(), 1);
        assert_eq!(ct_is_zero(&B).unwrap_u8(), 0);
    }

    #[test]
    fn ct_lt() {
        use super::ct_lt;

        assert_eq!(ct_lt(&A, &A).unwrap_u8(), 0);
        assert_eq!(ct_lt(&B, &B).unwrap_u8(), 0);
        assert_eq!(ct_lt(&C, &C).unwrap_u8(), 0);
        assert_eq!(ct_lt(&D, &D).unwrap_u8(), 0);
        assert_eq!(ct_lt(&E, &E).unwrap_u8(), 0);
        assert_eq!(ct_lt(&F, &F).unwrap_u8(), 0);

        assert_eq!(ct_lt(&A, &B).unwrap_u8(), 1);
        assert_eq!(ct_lt(&A, &C).unwrap_u8(), 1);
        assert_eq!(ct_lt(&B, &A).unwrap_u8(), 0);
        assert_eq!(ct_lt(&C, &A).unwrap_u8(), 0);

        assert_eq!(ct_lt(&B, &C).unwrap_u8(), 1);
        assert_eq!(ct_lt(&B, &D).unwrap_u8(), 1);
        assert_eq!(ct_lt(&C, &B).unwrap_u8(), 0);
        assert_eq!(ct_lt(&D, &B).unwrap_u8(), 0);

        assert_eq!(ct_lt(&C, &D).unwrap_u8(), 1);
        assert_eq!(ct_lt(&C, &E).unwrap_u8(), 1);
        assert_eq!(ct_lt(&D, &C).unwrap_u8(), 0);
        assert_eq!(ct_lt(&E, &C).unwrap_u8(), 0);

        assert_eq!(ct_lt(&E, &F).unwrap_u8(), 1);
        assert_eq!(ct_lt(&F, &E).unwrap_u8(), 0);
    }
}
