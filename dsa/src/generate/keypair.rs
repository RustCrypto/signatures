//!
//! Generate a DSA keypair
//!

use crate::{generate::components, Components, PrivateKey, PublicKey};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::{CryptoRng, RngCore};

/// Generate a new keypair
#[inline]
pub fn keypair<R>(rng: &mut R, components: Components) -> PrivateKey
where
    R: CryptoRng + RngCore + ?Sized,
{
    let x = rng.gen_biguint_range(&BigUint::one(), components.q());
    let y = components::public(&components, &x);

    let public_key = PublicKey::from_components(components, y);
    PrivateKey::from_components(public_key, x)
}
