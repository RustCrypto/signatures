// We abused the deprecated attribute for unsecure key sizes
// But we want to use those small key sizes for fast tests
#![allow(deprecated)]

use dsa::{consts::DSA_1024_160, Components, PrivateKey, PublicKey};
use num_bigint::BigUint;
use num_traits::One;
use pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};

fn generate_public_key() -> PublicKey {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, DSA_1024_160);
    let private_key = PrivateKey::generate(&mut rng, components);

    private_key.public_key().clone()
}

#[test]
fn encode_decode_public_key() {
    let public_key = generate_public_key();
    let encoded_public_key = public_key.to_public_key_pem(LineEnding::LF).unwrap();
    let decoded_public_key = PublicKey::from_public_key_pem(&encoded_public_key).unwrap();

    assert_eq!(public_key, decoded_public_key);
}

#[test]
fn validate_public_key() {
    let public_key = generate_public_key();
    let p = public_key.components().p();
    let q = public_key.components().q();

    // Taken from the parameter validation from bouncy castle
    assert_eq!(public_key.y().modpow(q, p), BigUint::one());
}
