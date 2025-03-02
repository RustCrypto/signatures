#![cfg(feature = "hazmat")]
//!
//! Generate a DSA keypair
//!

use crate::{Components, VerifyingKey, generate::components, signing_key::SigningKey};
use crypto_bigint::{BoxedUint, NonZero, RandomMod};
use signature::rand_core::CryptoRng;

/// Generate a new keypair
#[inline]
pub fn keypair<R: CryptoRng + ?Sized>(rng: &mut R, components: Components) -> SigningKey {
    let (x, y) = loop {
        let x = 'gen_x: loop {
            let x = BoxedUint::random_mod(rng, components.q());
            if let Some(x) = NonZero::new(x).into() {
                break 'gen_x x;
            }
        };

        if let Some(y) = components::public(&components, &x).into_option() {
            break (x, y);
        }
    };

    VerifyingKey::from_components(components, y)
        .and_then(|verifying_key| SigningKey::from_components(verifying_key, x))
        .expect("[Bug] Newly generated keypair considered invalid")
}
