//!
//! Generate a per-message secret number
//!

use crate::{signing_key::SigningKey, Components};
use alloc::{vec, vec::Vec};
use core::cmp::min;
use crypto_bigint::{BoxedUint, NonZero, RandomBits};
use digest::{core_api::BlockSizeUser, Digest, FixedOutputReset};
use rfc6979::HmacDrbg;
use signature::rand_core::CryptoRngCore;
use zeroize::Zeroize;

/// Reduce the hash into an RFC-6979 appropriate form
fn reduce_hash(q: &NonZero<BoxedUint>, hash: &[u8]) -> Vec<u8> {
    // Reduce the hash modulo Q
    let q_byte_len = q.bits() / 8;

    let hash_len = min(hash.len(), q_byte_len as usize);
    let hash = &hash[..hash_len];

    let hash = BoxedUint::from_be_slice(hash, (hash.len() * 8) as u32).unwrap();
    let mut reduced = Vec::from((hash % q).to_be_bytes());

    while reduced.len() < q_byte_len as usize {
        reduced.insert(0, 0);
    }

    reduced
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
    let k_size = (q.bits() / 8) as usize;
    let hash = reduce_hash(q, hash);

    let mut x_bytes = signing_key.x().to_be_bytes();
    let mut hmac = HmacDrbg::<D>::new(&x_bytes, &hash, &[]);
    x_bytes.zeroize();

    let mut buffer = vec![0; k_size];
    loop {
        hmac.fill_bytes(&mut buffer);

        let k = BoxedUint::from_be_slice(&buffer, (buffer.len() * 8) as u32).unwrap();
        if let Some(inv_k) = k.inv_mod(q).into() {
            if k > BoxedUint::zero() && k < **q {
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
