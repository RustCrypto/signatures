use dsa::{consts::DSA_2048_256, Components, PrivateKey};

fn main() {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, DSA_2048_256);
    let private_key = PrivateKey::generate(&mut rng, components);
    let _public_key = private_key.public_key();
}
