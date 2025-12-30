#![cfg(feature = "hazmat")]

use dsa::{Components, KeySize, SigningKey};
use getrandom::rand_core::TryRngCore;

fn main() {
    let mut rng = getrandom::SysRng.unwrap_err();
    let components = Components::generate(&mut rng, KeySize::DSA_2048_256);
    let signing_key = SigningKey::generate(&mut rng, components);
    let _verifying_key = signing_key.verifying_key();
}
