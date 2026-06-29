#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division_remainder_used,
    reason = "TODO"
)]

//! ## Usage
//!
//! See also: [`KGenerator`] documentation.
//!
//! ```
//! use hex_literal::hex;
//! use rfc6979::bigint::U256;
//! use sha2::{Digest, Sha256};
//!
//! // NIST P-256 field modulus
//! const NIST_P256_MODULUS: U256 = U256::from_be_hex(
//!     "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
//! );
//!
//! // Private key for RFC6979 NIST P256/SHA256 test case (see RFC6979 Appendix A.2.5).
//! // WARNING: don't hardcode private keys in your source code!
//! const RFC6979_KEY: [u8; 32] =
//!     hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
//!
//! // Test message for RFC6979 NIST P256/SHA256 test case
//! const RFC6979_MSG: &[u8] = b"sample";
//!
//! // Expected K for RFC6979 NIST P256/SHA256 test case
//! const RFC6979_EXPECTED_K: [u8; 32] =
//!     hex!("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
//!
//! let h = Sha256::digest(RFC6979_MSG);
//! let aad = b"";
//! let mut kgen = rfc6979::KGenerator::<Sha256, U256>::new(&RFC6979_KEY, &h, aad, &NIST_P256_MODULUS);
//!
//! let mut k = [0u8; U256::BYTES];
//! kgen.fill_next_k(&mut k);
//! assert_eq!(k, RFC6979_EXPECTED_K);
//! ```

mod hmac_drbg;

pub use bigint;
pub use hmac;
pub use hmac::digest::array::typenum::consts;

use crate::hmac_drbg::HmacDrbg;
use bigint::{Encoding, Limb, Unsigned};
use core::fmt;
use hmac::digest::{Digest, FixedOutput, FixedOutputReset, block_api::BlockSizeUser};

/// Deterministic generator for the ephemeral scalar `k` as used by (EC)DSA.
pub struct KGenerator<'a, D, U>
where
    D: Digest + BlockSizeUser + FixedOutput + FixedOutputReset,
{
    drbg: HmacDrbg<D>,
    q: &'a U,
}

impl<'a, D, U> KGenerator<'a, D, U>
where
    D: Digest + BlockSizeUser + FixedOutput + FixedOutputReset,
    U: Unsigned + Encoding,
{
    /// Initialize `k` generator.
    ///
    /// Accepts the following parameters and inputs:
    ///
    /// - `x`: secret key
    /// - `h`: raw hash/digest of input message
    /// - `data`: additional associated data, e.g. CSRNG output used as added entropy
    /// - `q`: field modulus
    pub fn new(x: &[u8], h: &[u8], data: &[u8], q: &'a U) -> Self {
        // Process `h` through `bits2octets`
        let mut h_scratch = q.to_be_bytes();
        let h_ref = &mut h_scratch.as_mut()[..x.len()];
        bits2octets(h, q, h_ref);

        let drbg = HmacDrbg::<D>::new(x, h_ref, data);
        Self { drbg, q }
    }

    /// Generate a candidate `k` value.
    ///
    /// This may be called repeatedly in the event a particular `k` is unsuitable, e.g. the
    /// resulting `r` value is zero.
    pub fn fill_next_k(&mut self, k: &mut [u8]) {
        debug_assert_eq!(k.len(), self.q.bits().div_ceil(8) as usize);

        loop {
            self.drbg.fill_bytes(k);
            let candidate_k = bits2int(k, self.q);
            if ((!candidate_k.is_zero()) & candidate_k.ct_lt(self.q)).to_bool() {
                int2octets(&candidate_k, self.q, k);
                return;
            }
        }
    }
}

impl<'a, D, U> fmt::Debug for KGenerator<'a, D, U>
where
    D: Digest + BlockSizeUser + FixedOutput + FixedOutputReset,
    U: Unsigned + Encoding,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KGenerator").finish_non_exhaustive()
    }
}

/// `bits2int` transform as defined in [RFC6979 §2.3.2]: "Bit String to Integer"
///
/// From the RFC:
///
/// >  The bits2int transform takes as input a sequence of blen bits and
/// >  outputs a non-negative integer that is less than 2^qlen.  It consists
/// >  of the following steps:
/// >
/// >  1. The sequence is first truncated or expanded to length qlen:
/// >
/// >  *  if qlen < blen, then the qlen leftmost bits are kept, and
/// >     subsequent bits are discarded;
/// >
/// >  *  otherwise, qlen-blen bits (of value zero) are added to the
/// >     left of the sequence (i.e., before the input bits in the
/// >     sequence order).
/// >
/// >  2. The resulting sequence is then converted to an integer value
/// >     using the big-endian convention: if input bits are called b_0
/// >     (leftmost) to b_(qlen-1) (rightmost), then the resulting value
/// >     is:
/// >
/// >        b_0*2^(qlen-1) + b_1*2^(qlen-2) + ... + b_(qlen-1)*2^0
/// >
/// >  The bits2int transform can also be described in the following way:
/// >  the input bit sequence (of length blen) is transformed into an
/// >  integer using the big-endian convention.  Then, if blen is greater
/// >  than qlen, the resulting integer is divided by two to the power
/// >  blen-qlen (Euclidian division: the remainder is discarded); in many
/// >  software implementations of arithmetics on big integers, that
/// >  division is equivalent to a "right shift" by blen-qlen bits.
///
/// [RFC6979 §2.3.2]: https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.2
#[inline]
fn bits2int<U>(mut b: &[u8], q: &U) -> U
where
    U: Unsigned + Encoding,
{
    debug_assert!(!b.is_empty());

    let qlen = q.bits();
    let mut blen = u32::try_from(b.len())
        .ok()
        .and_then(|len| len.checked_mul(8))
        .expect("overflow");

    let bits_diff = blen.saturating_sub(qlen);

    // Ensure `b` is within one octet of the length of `q`. This helps ensure we don't exceed the
    // capacity of `U`. This effectively emulates the right shift described in the RFC by truncating
    // the least significant bytes.
    let bytes_to_discard = bits_diff as usize / 8;
    if bytes_to_discard > 0 {
        b = &b[..b.len() - bytes_to_discard];
        blen -= (bytes_to_discard as u32) * 8;
    }

    let mut int = U::from_be_slice_truncated(b, blen);
    int.shr_assign(blen.saturating_sub(qlen));
    int
}

/// `int2octets` transform as defined in [RFC6979 §2.3.3]: "Integer to Octet String"
///
/// From the RFC:
///
/// > An integer value x less than q (and, in particular, a value that has
/// > been taken modulo q) can be converted into a sequence of rlen bits,
/// > where rlen = 8*ceil(qlen/8).  This is the sequence of bits obtained
/// > by big-endian encoding.  In other words, the sequence bits x_i (for i
/// > ranging from 0 to rlen-1) are such that:
/// >
/// > x = x_0*2^(rlen-1) + x_1*2^(rlen-2) + ... + x_(rlen-1)
/// >
/// > We call this transform int2octets.  Since rlen is a multiple of 8
/// > (the smallest multiple of 8 that is not smaller than qlen), then the
/// > resulting sequence of bits is also a sequence of octets, hence the
/// > name.
///
/// [RFC6979 §2.3.3]: https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.3
fn int2octets<'a, U: Unsigned>(x: &U, q: &U, out: &'a mut [u8]) -> &'a [u8] {
    debug_assert!(x < q);
    let qlen = q.bits();
    let rlen = qlen.div_ceil(8) as usize; // NOTE: rlen in RFC is bits; we use bytes

    debug_assert!(out.len() >= rlen);
    let out = &mut out[..rlen];

    let xlimbs: &[Limb] = x.as_ref();
    for (limb, chunk) in xlimbs.iter().zip(out.rchunks_mut(Limb::BYTES)) {
        let bytes = limb.to_be_bytes();
        let offset = Limb::BYTES.saturating_sub(chunk.len());
        chunk.copy_from_slice(&bytes[offset..]);
    }

    out
}

/// `bits2octets` transform as defined in [RFC6979 §2.3.4]: "Bit String to Octet String"
///
/// From the RFC:
///
/// > The bits2octets transform takes as input a sequence of blen bits and
/// > outputs a sequence of rlen bits.  It consists of the following steps:
/// >
/// > 1. The input sequence b is converted into an integer value z1
/// >    through the bits2int transform:
/// >
/// >       z1 = bits2int(b)
/// >
/// > 2. z1 is reduced modulo q, yielding z2 (an integer between 0 and
/// >    q-1, inclusive):
/// >
/// >       z2 = z1 mod q
/// >
/// >    Note that since z1 is less than 2^qlen, that modular reduction
/// >    can be implemented with a simple conditional subtraction:
/// >    z2 = z1-q if that value is non-negative; otherwise, z2 = z1.
/// >
/// > 3.  z2 is transformed into a sequence of octets (a sequence of rlen
/// >    bits) by applying int2octets.
///
/// [RFC6979 §2.3.3]: https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.3
fn bits2octets<'a, U>(b: &[u8], q: &U, out: &'a mut [u8]) -> &'a [u8]
where
    U: Unsigned + Encoding,
{
    let z1 = bits2int(b, q);
    let mut z2 = z1.wrapping_sub(q);

    // Perform modular reduction via conditional subtraction, since we know `z1` is the same bit
    // length as `q` and therefore only one such subtraction is required.
    // (see description of this approach in the rustdoc)
    z2.ct_assign(&z1, z1.ct_lt(q));
    int2octets(&z2, q, out)
}

#[cfg(test)]
mod tests {
    mod bits2int {
        use crate::bits2int;
        use bigint::{BitOps, BoxedUint, U256};

        #[test]
        fn left_pads_when_blen_is_shorter_than_qlen() {
            let q = U256::from_u64(0x800);
            assert_eq!(bits2int(&[0x2a], &q), U256::from_u64(0x2a));
        }

        #[test]
        fn keeps_exact_qlen_bits() {
            let q = U256::from_u64(0x80);
            assert_eq!(bits2int(&[0xab], &q), U256::from_u64(0xab));
        }

        // K-163 inspired test case
        #[test]
        fn discards_trailing_bytes_then_shifts_remaining_bits() {
            let q = U256::ONE.shl_vartime(162);
            let b = [0xff; 32];

            assert_eq!(
                bits2int(&b, &q),
                U256::from_be_hex(
                    "000000000000000000000007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                )
            );
        }

        #[test]
        fn truncates_leftmost_bits_on_byte_boundary() {
            let q = U256::from_u64(0x80);
            assert_eq!(bits2int(&[0xab, 0xcd], &q), U256::from_u64(0xab));
        }

        #[test]
        fn truncates_leftmost_bits_across_partial_byte() {
            let q = U256::from_u64(0x800);
            assert_eq!(bits2int(&[0xab, 0xcd], &q), U256::from_u64(0xabc));
        }

        #[test]
        fn boxed_matches_fixed_for_short_input() {
            let q = U256::from_be_hex(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            );
            let q_boxed = BoxedUint::from_be_slice(&q.to_be_bytes(), q.bits_precision()).unwrap();
            let h = [0xab; 20];
            assert_eq!(bits2int(&h, &q_boxed), bits2int(&h, &q),);
        }
    }

    mod int2octets {
        use crate::int2octets;
        use bigint::U256;

        #[test]
        fn encodes_single_octet() {
            let q = U256::from_u64(0x80);
            let x = U256::from_u64(0x2a);
            let mut out = [0u8; 32];
            assert_eq!(int2octets(&x, &q, &mut out), &[0x2a]);
        }

        #[test]
        fn left_pads_to_qlen_octets() {
            let q = U256::from_u64(0x800);
            let x = U256::from_u64(0x2a);
            let mut out = [0u8; 32];
            assert_eq!(int2octets(&x, &q, &mut out), &[0x00, 0x2a]);
        }

        #[test]
        fn int2octets_preserves_full_width_value() {
            let q = U256::from_u64(0x800);
            let x = U256::from_u64(0x7ff);
            let mut out = [0u8; 32];
            assert_eq!(int2octets(&x, &q, &mut out), &[0x07, 0xff]);
        }
    }

    mod bits2octets {
        use crate::bits2octets;
        use bigint::{BoxedUint, U256};

        const EXAMPLE_Q: U256 =
            U256::from_be_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

        #[test]
        fn already_reduced() {
            let q = U256::from_u64(0x80);
            let mut out = [0u8; 32];
            assert_eq!(bits2octets(&[0x2a], &q, &mut out), &[0x2a]);
        }

        #[test]
        fn needs_reduction() {
            let q = U256::from_u64(0x80);
            let mut out = [0u8; 32];
            assert_eq!(bits2octets(&[0xff], &q, &mut out), &[0x7f]);
        }

        #[test]
        fn left_pads_when_blen_is_shorter_than_qlen() {
            let h = [0xab; 20];
            let mut out = [0u8; 32];

            assert_eq!(
                bits2octets(&h, &EXAMPLE_Q, &mut out),
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                ],
            );
        }

        #[test]
        fn boxed_left_pads_short_hash_to_rlen() {
            let boxed_q = BoxedUint::from_be_slice(&EXAMPLE_Q.to_be_bytes(), 256).unwrap();
            let h = [0xab; 20];
            let mut out = [0u8; 32];

            assert_eq!(
                bits2octets(&h, &boxed_q, &mut out),
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                ],
            );
        }

        #[test]
        fn boxed_160_bit_hash_with_256_bit_q() {
            let q = U256::from_be_hex(
                "87A8E61DB4B6663CFFBBD19C6519599998CEEF608660DD0F25D2CE4EDDBF8A9B",
            );

            let boxed_q = BoxedUint::from_be_slice(&q.to_be_bytes(), 256).unwrap();

            let h = [
                0x81, 0x53, 0x2b, 0x5b, 0xe0, 0x21, 0xe9, 0xb6, 0xe9, 0x87, 0xf3, 0x37, 0x66, 0x31,
                0x97, 0x4e, 0xa3, 0x1b, 0x72, 0x37,
            ];

            let mut out = [0u8; 32];
            let actual = bits2octets(&h, &boxed_q, &mut out);
            assert_eq!(&actual[..12], &[0u8; 12]);
            assert_eq!(&actual[12..], &h);
        }
    }
}
