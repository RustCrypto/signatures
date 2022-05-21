use dsa::{Components, KeySize, SigningKey};

fn main() {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, KeySize::DSA_2048_256);
    let signing_key = SigningKey::generate(&mut rng, components);
    let _verifying_key = signing_key.verifying_key();
}
