//!
//! Generate a per-message secret number
//!

use crate::Components;
use num_bigint::{BigUint, ModInverse, RandBigInt};
use num_traits::{One, Zero};
use rand::{CryptoRng, RngCore};

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
