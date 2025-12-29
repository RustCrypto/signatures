#![cfg(feature = "hazmat")]
//!
//! Generate a DSA keypair
//!

use crate::{Components, VerifyingKey, generate::components, signing_key::SigningKey};
use crypto_bigint::{BoxedUint, NonZero, RandomMod};
use signature::rand_core::CryptoRng;

/// Generate a new keypair
#[inline]
pub(crate) fn keypair<R: CryptoRng + ?Sized>(rng: &mut R, components: Components) -> SigningKey {
    #[inline]
    fn find_non_zero_x<R: CryptoRng + ?Sized>(
        rng: &mut R,
        components: &Components,
    ) -> NonZero<BoxedUint> {
        loop {
            let x = BoxedUint::random_mod_vartime(rng, components.q());
            if let Some(x) = NonZero::new(x).into() {
                return x;
            }
        }
    }

    #[inline]
    fn find_components<R: CryptoRng + ?Sized>(
        rng: &mut R,
        components: &Components,
    ) -> (NonZero<BoxedUint>, NonZero<BoxedUint>) {
        loop {
            let x = find_non_zero_x(rng, components);

            if let Some(y) = components::public(components, &x).into_option() {
                return (x, y);
            }
        }
    }

    let (x, y) = find_components(rng, &components);

    VerifyingKey::from_components(components, y.get())
        .and_then(|verifying_key| SigningKey::from_components(verifying_key, x.get()))
        .expect("[Bug] Newly generated keypair considered invalid")
}
