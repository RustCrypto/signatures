#![cfg(feature = "hazmat")]
//!
//! Generate a DSA keypair
//!

use crate::{generate::components, signing_key::SigningKey, Components, VerifyingKey};
use crypto_bigint::{BoxedUint, NonZero, RandomMod};
use signature::rand_core::CryptoRngCore;

/// Generate a new keypair
#[inline]
pub fn keypair(rng: &mut impl CryptoRngCore, components: Components) -> SigningKey {
    let x = loop {
        let x = BoxedUint::random_mod(rng, components.q());
        if let Some(x) = NonZero::new(x).into() {
            break x;
        }
    };

    let y = components::public(&components, &x);

    VerifyingKey::from_components(components, y)
        .and_then(|verifying_key| SigningKey::from_components(verifying_key, x))
        .expect("[Bug] Newly generated keypair considered invalid")
}
