//! Key generation example.

#![cfg(feature = "hazmat")]

use dsa::{Components, KeySize, SigningKey};
use getrandom::{SysRng, rand_core::UnwrapErr};

fn main() {
    let mut rng = UnwrapErr(SysRng);
    let components =
        Components::try_generate_from_rng_with_key_size(&mut rng, KeySize::DSA_2048_256).unwrap();
    let signing_key =
        SigningKey::try_generate_from_rng_with_components(&mut rng, components).unwrap();
    let _verifying_key = signing_key.verifying_key();
}
