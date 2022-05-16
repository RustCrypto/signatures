//!
//! Generate a per-message secret number
//!

use crate::{Components, SigningKey};
use alloc::{vec, vec::Vec};
use core::cmp::min;
use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore},
    typenum::{IsLess, Le, NonZero},
    FixedOutput, HashMarker, OutputSizeUser,
};
use num_bigint::{BigUint, ModInverse, RandBigInt};
use num_traits::{One, Zero};
use rand::{CryptoRng, RngCore};
use rfc6979::HmacDrbg;
use zeroize::Zeroize;

/// Reduce the hash into an RFC-6979 appropriate form
fn reduce_hash(q: &BigUint, hash: &[u8]) -> Vec<u8> {
    // Reduce the hash modulo Q
    let q_byte_len = q.bits() / 8;

    let hash_len = min(hash.len(), q_byte_len);
    let hash = &hash[..hash_len];

    let hash = BigUint::from_bytes_be(hash);
    let mut reduced = (hash % q).to_bytes_be();

    while reduced.len() < q_byte_len {
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
pub fn secret_number_rfc6979<D>(signing_key: &SigningKey, hash: &[u8]) -> (BigUint, BigUint)
where
    D: CoreProxy + FixedOutput,
    D::Core: BlockSizeUser
        + BufferKindUser<BufferKind = Eager>
        + Clone
        + Default
        + FixedOutputCore
        + HashMarker
        + OutputSizeUser<OutputSize = D::OutputSize>,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let q = signing_key.verifying_key().components().q();
    let k_size = q.bits() / 8;
    let hash = reduce_hash(q, hash);

    let mut x_bytes = signing_key.x().to_bytes_be();
    let mut hmac = HmacDrbg::<D>::new(&x_bytes, &hash, &[]);
    x_bytes.zeroize();

    let mut buffer = vec![0; k_size];
    loop {
        hmac.fill_bytes(&mut buffer);

        let k = BigUint::from_bytes_be(&buffer);
        if let Some(inv_k) = (&k).mod_inverse(q) {
            let inv_k = inv_k.to_biguint().unwrap();

            if k > BigUint::zero() && &k < q {
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
pub fn secret_number<R>(rng: &mut R, components: &Components) -> Option<(BigUint, BigUint)>
where
    R: CryptoRng + RngCore + ?Sized,
{
    let q = components.q();
    let n = q.bits();

    // Attempt to try a fitting secret number
    // Give up after 4096 tries
    for _ in 0..4096 {
        let c = rng.gen_biguint(n + 64);
        let k = (c % (q - BigUint::one())) + BigUint::one();

        if let Some(inv_k) = (&k).mod_inverse(q) {
            let inv_k = inv_k.to_biguint().unwrap();

            // `k` and `k^-1` both have to be in the range `[1, q-1]`
            if (inv_k > BigUint::zero() && &inv_k < q) && (k > BigUint::zero() && &k < q) {
                return Some((k, inv_k));
            }
        }
    }

    None
}
