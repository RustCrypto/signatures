//! Constant-time helpers.
// TODO(tarcieri): replace this with `crypto-bigint`?

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time test that a given byte slice contains only zeroes.
#[inline]
pub(crate) fn is_zero(n: &[u8]) -> Choice {
    let mut ret = Choice::from(1);

    for byte in n {
        ret.conditional_assign(&Choice::from(0), byte.ct_ne(&0));
    }

    ret
}

/// Constant-time less than.
///
/// Inputs are interpreted as little endian integers.
pub(crate) fn lt(a: &[u8], b: &[u8]) -> Choice {
    debug_assert_eq!(a.len(), b.len());

    let mut borrow = 0u16;

    for (a_byte, b_byte) in a.iter().zip(b.iter()) {
        let diff = (*a_byte as u16)
            .wrapping_sub(*b_byte as u16)
            .wrapping_sub(borrow);

        borrow = (diff >> 8) & 1;
    }

    Choice::from(borrow as u8)
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
        use super::is_zero;
        assert_eq!(is_zero(&A).unwrap_u8(), 1);
        assert_eq!(is_zero(&B).unwrap_u8(), 0);
    }

    #[test]
    fn ct_lt() {
        use super::lt;

        assert_eq!(lt(&A, &A).unwrap_u8(), 0);
        assert_eq!(lt(&B, &B).unwrap_u8(), 0);
        assert_eq!(lt(&C, &C).unwrap_u8(), 0);
        assert_eq!(lt(&D, &D).unwrap_u8(), 0);
        assert_eq!(lt(&E, &E).unwrap_u8(), 0);
        assert_eq!(lt(&F, &F).unwrap_u8(), 0);

        assert_eq!(lt(&A, &B).unwrap_u8(), 1);
        assert_eq!(lt(&A, &C).unwrap_u8(), 1);
        assert_eq!(lt(&B, &A).unwrap_u8(), 0);
        assert_eq!(lt(&C, &A).unwrap_u8(), 0);

        assert_eq!(lt(&C, &B).unwrap_u8(), 1);
        assert_eq!(lt(&B, &D).unwrap_u8(), 1);
        assert_eq!(lt(&B, &C).unwrap_u8(), 0);
        assert_eq!(lt(&D, &B).unwrap_u8(), 0);

        assert_eq!(lt(&C, &D).unwrap_u8(), 1);
        assert_eq!(lt(&C, &E).unwrap_u8(), 1);
        assert_eq!(lt(&D, &C).unwrap_u8(), 0);
        assert_eq!(lt(&E, &C).unwrap_u8(), 0);

        assert_eq!(lt(&E, &F).unwrap_u8(), 1);
        assert_eq!(lt(&F, &E).unwrap_u8(), 0);
    }
}
