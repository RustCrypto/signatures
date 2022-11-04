//!
//! Generate DSA key components
//!

use crate::{
    generate::{calculate_bounds, generate_prime},
    size::KeySize,
    two, Components,
};
use num_bigint::{prime::probably_prime, BigUint, RandBigInt};
use num_traits::One;
use signature::rand_core::CryptoRngCore;

/// Numbers of miller-rabin rounds performed to determine primality
const MR_ROUNDS: usize = 64;

/// Generate the common components p, q, and g
///
/// # Returns
///
/// Tuple of three `BigUint`s. Ordered like this `(p, q, g)`
pub fn common(
    rng: &mut impl CryptoRngCore,
    KeySize { l, n }: KeySize,
) -> (BigUint, BigUint, BigUint) {
    // Calculate the lower and upper bounds of p and q
    let (p_min, p_max) = calculate_bounds(l);
    let (q_min, q_max) = calculate_bounds(n);

    let (p, q) = 'gen_pq: loop {
        let q = generate_prime(n as usize, rng);
        if q < q_min || q > q_max {
            continue;
        }

        // Attempt to find a prime p which has a subgroup of the order q
        for _ in 0..4096 {
            let m = 'gen_m: loop {
                let m = rng.gen_biguint(l as usize);
                if m > p_min && m < p_max {
                    break 'gen_m m;
                }
            };
            let mr = &m % (two() * &q);
            let p = m - mr + BigUint::one();

            if probably_prime(&p, MR_ROUNDS) {
                break 'gen_pq (p, q);
            }
        }
    };

    // Generate g using the unverifiable method as defined by Appendix A.2.1
    let e = (&p - BigUint::one()) / &q;
    let mut h = BigUint::one();
    let g = loop {
        let g = h.modpow(&e, &p);
        if !g.is_one() {
            break g;
        }

        h += BigUint::one();
    };

    (p, q, g)
}

/// Calculate the public component from the common components and the private component
#[inline]
pub fn public(components: &Components, x: &BigUint) -> BigUint {
    let p = components.p();
    let g = components.g();

    g.modpow(x, p)
}
