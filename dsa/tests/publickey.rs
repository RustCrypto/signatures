// We abused the deprecated attribute for unsecure key sizes
// But we want to use those small key sizes for fast tests
#![allow(deprecated)]

use dsa::{consts::DSA_1024_160, Components, PrivateKey, PublicKey};
use num_bigint::BigUint;
use num_traits::One;
use pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};

const OPENSSL_PEM_PUBLIC_KEY: &str = include_str!("pems/public.pem");

fn generate_public_key() -> PublicKey {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, DSA_1024_160);
    let private_key = PrivateKey::generate(&mut rng, components);

    private_key.public_key().clone()
}

#[test]
fn decode_encode_openssl_public_key() {
    let public_key = PublicKey::from_public_key_pem(OPENSSL_PEM_PUBLIC_KEY)
        .expect("Failed to decode PEM encoded OpenSSL public key");
    assert!(public_key.is_valid());

    let reencoded_public_key = public_key
        .to_public_key_pem(LineEnding::default())
        .expect("Failed to encode public key into PEM representation");

    assert_eq!(reencoded_public_key, OPENSSL_PEM_PUBLIC_KEY);
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
