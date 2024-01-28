//!
//! Generate a per-message secret number
//!

use crate::{Components, SigningKey};
use alloc::vec;
use crypto_bigint::{BoxedUint, Integer, InvMod, NonZero, RandomBits};
use digest::{core_api::BlockSizeUser, Digest, FixedOutputReset};
use signature::rand_core::CryptoRngCore;
use zeroize::Zeroizing;

fn strip_leading_zeros(buffer: &[u8], desired_size: usize) -> &[u8] {
    &buffer[(buffer.len() - desired_size)..]
}

/// Generate a per-message secret number k deterministically using the method described in RFC 6979
///
/// # Returns
///
/// Secret number k and its modular multiplicative inverse with q
#[inline]
pub fn secret_number_rfc6979<D>(signing_key: &SigningKey, hash: &[u8]) -> (BoxedUint, BoxedUint)
where
    D: Digest + BlockSizeUser + FixedOutputReset,
{
    let q = signing_key.verifying_key().components().q();
    let size = (q.bits() / 8) as usize;

    // Reduce hash mod q
    let hash = BoxedUint::from_be_slice(hash, (hash.len() * 8) as u32).unwrap();
    let hash = (hash % q).to_be_bytes();
    let hash = strip_leading_zeros(&hash, size);

    let q_bytes = q.to_be_bytes();
    let q_bytes = strip_leading_zeros(&q_bytes, size);

    let x_bytes = Zeroizing::new(signing_key.x().to_be_bytes());
    let x_bytes = strip_leading_zeros(&x_bytes, size);

    let mut buffer = vec![0; size];
    loop {
        rfc6979::generate_k_mut::<D>(x_bytes, q_bytes, hash, &[], &mut buffer);

        let k = BoxedUint::from_be_slice(&buffer, (buffer.len() * 8) as u32).unwrap();
        if let Some(inv_k) = k.inv_mod(q).into() {
            if (bool::from(k.is_nonzero())) & (k < **q) {
                debug_assert!(bool::from(k.is_odd()));
                return (k, inv_k);
            }
        }
    }
}

/// Generate a per-message secret number k according to Appendix B.2.1
///
/// # Returns
///
/// Secret number k and its modular multiplicative inverse with q
#[inline]
pub fn secret_number(
    rng: &mut impl CryptoRngCore,
    components: &Components,
) -> Option<(BoxedUint, BoxedUint)> {
    let q = components.q();
    let n = q.bits();

    // Attempt to try a fitting secret number
    // Give up after 4096 tries
    for _ in 0..4096 {
        let c = BoxedUint::random_bits(rng, n + 64);
        let k = (c % NonZero::new(&**q - &BoxedUint::one()).unwrap()) + BoxedUint::one();

        if let Some(inv_k) = k.inv_mod(q).into() {
            // `k` and `k^-1` both have to be in the range `[1, q-1]`
            if (inv_k > BoxedUint::zero() && inv_k < **q) && (k > BoxedUint::zero() && k < **q) {
                return Some((k, inv_k));
            }
        }
    }

    None
}
