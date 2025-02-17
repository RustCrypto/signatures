//!
//! Generate DSA key components
//!

use crate::{
    Components,
    generate::{calculate_bounds, generate_prime},
    size::KeySize,
    two,
};
use crypto_bigint::{
    BoxedUint, NonZero, Odd, RandomBits,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use crypto_primes::{Flavor, is_prime};
use signature::rand_core::CryptoRng;

/// Generate the common components p, q, and g
///
/// # Returns
///
/// Tuple of three `BoxedUint`s. Ordered like this `(p, q, g)`
pub fn common<R: CryptoRng + ?Sized>(
    rng: &mut R,
    KeySize { l, n }: KeySize,
) -> (NonZero<BoxedUint>, NonZero<BoxedUint>, NonZero<BoxedUint>) {
    // Calculate the lower and upper bounds of p and q
    let (p_min, p_max) = calculate_bounds(l);
    let (q_min, q_max) = calculate_bounds(n);

    let (p, q) = 'gen_pq: loop {
        let q = generate_prime(n, rng);
        if q < q_min || q > q_max {
            continue;
        }
        let q = NonZero::new(q).unwrap();

        // Attempt to find a prime p which has a subgroup of the order q
        for _ in 0..4096 {
            let m = 'gen_m: loop {
                let m = BoxedUint::random_bits(rng, l);
                if m > p_min && m < p_max {
                    break 'gen_m m;
                }
            };
            let mr = &m % NonZero::new(two() * &*q).unwrap();
            let p = m - mr + BoxedUint::one();
            let p = NonZero::new(p).unwrap();

            if is_prime(Flavor::Any, &*p) {
                break 'gen_pq (p, q);
            }
        }
    };

    // Generate g using the unverifiable method as defined by Appendix A.2.1
    let e = (&*p - &BoxedUint::one()) / &q;
    let mut h = BoxedUint::one();
    let g = loop {
        let params = BoxedMontyParams::new_vartime(Odd::new((*p).clone()).unwrap());
        let form = BoxedMontyForm::new(h.clone(), params);
        let g = form.pow(&e).retrieve();

        if !bool::from(g.is_one()) {
            break NonZero::new(g).unwrap();
        }

        h = h + BoxedUint::one();
    };

    (p, q, g)
}

/// Calculate the public component from the common components and the private component
#[inline]
pub fn public(components: &Components, x: &NonZero<BoxedUint>) -> NonZero<BoxedUint> {
    let p = components.p();
    let g = components.g();

    let params = BoxedMontyParams::new_vartime(Odd::new((**p).clone()).unwrap());
    let form = BoxedMontyForm::new((**g).clone(), params);

    NonZero::new(form.pow(x).retrieve()).unwrap()
}
