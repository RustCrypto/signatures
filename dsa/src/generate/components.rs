//!
//! Generate DSA key components
//!

use crate::{
    generate::{calculate_bounds, generate_prime},
    size::KeySize,
    two,
};
use crypto_bigint::{
    BoxedUint, NonZero, Odd, RandomBits, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use crypto_primes::{Flavor, is_prime};
use signature::rand_core::CryptoRng;

#[cfg(feature = "hazmat")]
use {crate::Components, crypto_bigint::CtOption};

/// Generate the common components p, q, and g
///
/// # Returns
///
/// Tuple of three `BoxedUint`s. Ordered like this `(p, q, g)`
pub(crate) fn common<R: CryptoRng + ?Sized>(
    rng: &mut R,
    KeySize { l, n }: KeySize,
) -> (Odd<BoxedUint>, NonZero<BoxedUint>, NonZero<BoxedUint>) {
    // Calculate the lower and upper bounds of p and q
    let (p_min, p_max) = calculate_bounds(l);
    let (q_min, q_max): (NonZero<_>, _) = calculate_bounds(n);

    let (p, q): (Odd<_>, _) = 'gen_pq: loop {
        let q = generate_prime(n, rng);
        if q < *q_min || q > *q_max {
            continue;
        }
        let q = NonZero::new(q)
            .expect("[bug] invariant violation, q is above q_min which itself is NonZero");

        // Attempt to find a prime p which has a subgroup of the order q
        for _ in 0..4096 {
            let m = 'gen_m: loop {
                let m = BoxedUint::random_bits(rng, l);

                if m > *p_min && m < *p_max {
                    break 'gen_m m;
                }
            };
            let rem = NonZero::new((two() * &*q).resize(m.bits_precision()))
                .expect("[bug] 2 * NonZero can't be zero");

            let mr = &m % &rem;
            let p = m - mr + BoxedUint::one();

            if is_prime(Flavor::Any, &p) {
                let p = Odd::new(p).expect("[bug] Any even number would be prime. P is at least 2^L and L is at least 1024.");
                break 'gen_pq (p, q);
            }
        }
    };

    // Q needs to be the same precision as P for the operations below.
    let q = q.resize(l);

    // Generate g using the unverifiable method as defined by Appendix A.2.1
    let e = (&*p - &BoxedUint::one()) / &q;
    let mut h = BoxedUint::one().resize(l);
    let g = loop {
        let params = BoxedMontyParams::new_vartime(p.clone());
        let form = BoxedMontyForm::new(h.clone(), params);
        let g = form.pow(&e).retrieve();

        if !bool::from(g.is_one()) {
            // TODO(baloo): shouldn't we check e can't be 1 here?
            //              and g could still be zero right? In which case just loop around?
            break NonZero::new(g).unwrap();
        }

        h += BoxedUint::one();
    };

    let q = q.resize(n);

    (p, q, g)
}

/// Calculate the public component from the common components and the private component
#[cfg(feature = "hazmat")]
#[inline]
pub(crate) fn public(
    components: &Components,
    x: &NonZero<BoxedUint>,
) -> CtOption<NonZero<BoxedUint>> {
    let p = components.p();
    let g = components.g();

    let params = BoxedMontyParams::new_vartime(p.clone());
    let form = BoxedMontyForm::new((**g).clone(), params);

    NonZero::new(form.pow(x).retrieve())
}
