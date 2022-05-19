//!
//! Generate a DSA keypair
//!

use crate::{generate::components, Components, SigningKey, VerifyingKey};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::{CryptoRng, RngCore};

/// Generate a new keypair
#[inline]
pub fn keypair<R>(rng: &mut R, components: Components) -> SigningKey
where
    R: CryptoRng + RngCore + ?Sized,
{
    let x = rng.gen_biguint_range(&BigUint::one(), components.q());
    let y = components::public(&components, &x);

    let verifying_key = VerifyingKey::from_components(components, y)
        .expect("[Bug] Newly generated verifying key considered invalid");
    SigningKey::from_components(verifying_key, x)
        .expect("[Bug] Newly generated signing key considered invalid")
}
