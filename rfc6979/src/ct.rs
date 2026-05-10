//! Constant-time helpers.
// TODO(tarcieri): replace this with `crypto-bigint`?

use ctutils::{Choice, CtEq};

/// Count the number of leading zeros in constant-time.
#[inline]
pub(crate) fn leading_zeros(n: &[u8]) -> u32 {
    n[0].leading_zeros()
}

/// Constant-time bitwise right shift.
#[inline]
pub(crate) fn rshift(n: &mut [u8], shift: u32) {
    debug_assert!(shift < 8);
    let mask = (1 << shift) - 1;
    let mut carry = 0;

    for byte in n.iter_mut() {
        let new_carry = (*byte & mask) << (8 - shift);
        *byte = (*byte >> shift) | carry;
        carry = new_carry;
    }
}

/// Constant-time test that a given byte slice contains only zeroes.
#[inline]
pub(crate) fn is_zero(n: &[u8]) -> Choice {
    let mut ret = Choice::from(1);

    for byte in n {
        ret &= byte.ct_eq(&0);
    }

    ret
}

/// Constant-time less than.
///
/// Inputs are interpreted as big endian integers.
#[inline]
pub(crate) fn lt(a: &[u8], b: &[u8]) -> Choice {
    debug_assert_eq!(a.len(), b.len());

    let mut borrow = 0;

    // Perform subtraction with borrow a byte-at-a-time, interpreting a
    // no-borrow condition as the less-than case
    for (&a, &b) in a.iter().zip(b.iter()).rev() {
        let c = u16::from(b).wrapping_add(borrow >> (u8::BITS - 1));
        borrow = u16::from(a).wrapping_sub(c) >> u8::BITS;
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
        use super::is_zero;
        assert!(is_zero(&A).to_bool());
        assert!(!is_zero(&B).to_bool());
    }

    #[test]
    fn ct_lt() {
        use super::lt;

        assert!(!lt(&A, &A).to_bool());
        assert!(!lt(&B, &B).to_bool());
        assert!(!lt(&C, &C).to_bool());
        assert!(!lt(&D, &D).to_bool());
        assert!(!lt(&E, &E).to_bool());
        assert!(!lt(&F, &F).to_bool());

        assert!(lt(&A, &B).to_bool());
        assert!(lt(&A, &C).to_bool());
        assert!(!lt(&B, &A).to_bool());
        assert!(!lt(&C, &A).to_bool());

        assert!(lt(&B, &C).to_bool());
        assert!(lt(&B, &D).to_bool());
        assert!(!lt(&C, &B).to_bool());
        assert!(!lt(&D, &B).to_bool());

        assert!(lt(&C, &D).to_bool());
        assert!(lt(&C, &E).to_bool());
        assert!(!lt(&D, &C).to_bool());
        assert!(!lt(&E, &C).to_bool());

        assert!(lt(&E, &F).to_bool());
        assert!(!lt(&F, &E).to_bool());
    }
}
