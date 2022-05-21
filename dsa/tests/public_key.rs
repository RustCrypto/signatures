// We abused the deprecated attribute for unsecure key sizes
// But we want to use those small key sizes for fast tests
#![allow(deprecated)]

use dsa::{Components, KeySize, SigningKey, VerifyingKey};
use num_bigint::BigUint;
use num_traits::One;
use pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};

const OPENSSL_PEM_PUBLIC_KEY: &str = include_str!("pems/public.pem");

fn generate_verifying_key() -> VerifyingKey {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, KeySize::DSA_1024_160);
    let signing_key = SigningKey::generate(&mut rng, components);

    signing_key.verifying_key().clone()
}

#[test]
fn decode_encode_openssl_verifying_key() {
    let verifying_key = VerifyingKey::from_public_key_pem(OPENSSL_PEM_PUBLIC_KEY)
        .expect("Failed to decode PEM encoded OpenSSL public key");

    let reencoded_verifying_key = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .expect("Failed to encode public key into PEM representation");

    assert_eq!(reencoded_verifying_key, OPENSSL_PEM_PUBLIC_KEY);
}

#[test]
fn encode_decode_verifying_key() {
    let verifying_key = generate_verifying_key();
    let encoded_verifying_key = verifying_key.to_public_key_pem(LineEnding::LF).unwrap();
    let decoded_verifying_key = VerifyingKey::from_public_key_pem(&encoded_verifying_key).unwrap();

    assert_eq!(verifying_key, decoded_verifying_key);
}

#[test]
fn validate_verifying_key() {
    let verifying_key = generate_verifying_key();
    let p = verifying_key.components().p();
    let q = verifying_key.components().q();

    // Taken from the parameter validation from bouncy castle
    assert_eq!(verifying_key.y().modpow(q, p), BigUint::one());
}
