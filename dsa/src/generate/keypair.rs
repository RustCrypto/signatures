//!
//! Generate a DSA keypair
//!

use crate::{generate::components, Components, SigningKey, VerifyingKey};
use digest::Digest;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::{CryptoRng, RngCore};

/// Generate a new keypair
#[inline]
pub fn keypair<R, D>(rng: &mut R, components: Components) -> SigningKey<D>
where
    R: CryptoRng + RngCore + ?Sized,
    D: Digest,
{
    let x = rng.gen_biguint_range(&BigUint::one(), components.q());
    let y = components::public(&components, &x);

    VerifyingKey::from_components(components, y)
        .and_then(|verifying_key| SigningKey::from_components(verifying_key, x))
        .expect("[Bug] Newly generated keypair considered invalid")
}
