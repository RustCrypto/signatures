// We abused the deprecated attribute for unsecure key sizes
// But we want to use those small key sizes for fast tests
#![allow(deprecated)]

use digest::Digest;
use dsa::{consts::DSA_1024_160, Components, PrivateKey};
use num_bigint::BigUint;
use num_traits::Zero;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use sha1::Sha1;
use signature::{DigestVerifier, RandomizedDigestSigner};

const OPENSSL_PEM_PRIVATE_KEY: &str = include_str!("pems/private.pem");

fn generate_keypair() -> PrivateKey {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, DSA_1024_160);
    PrivateKey::generate(&mut rng, components)
}

#[test]
fn decode_encode_openssl_private_key() {
    let private_key = PrivateKey::from_pkcs8_pem(OPENSSL_PEM_PRIVATE_KEY)
        .expect("Failed to decode PEM encoded OpenSSL key");
    assert!(private_key.is_valid());

    let reencoded_private_key = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode private key into PEM representation");

    assert_eq!(*reencoded_private_key, OPENSSL_PEM_PRIVATE_KEY);
}

#[test]
fn encode_decode_private_key() {
    let private_key = generate_keypair();
    let encoded_private_key = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let decoded_private_key = PrivateKey::from_pkcs8_pem(&encoded_private_key).unwrap();

    assert_eq!(private_key, decoded_private_key);
}

#[test]
fn sign_and_verify() {
    const DATA: &[u8] = b"SIGN AND VERIFY THOSE BYTES";

    let private_key = generate_keypair();
    let public_key = private_key.public_key();

    let signature =
        private_key.sign_digest_with_rng(rand::thread_rng(), Sha1::new().chain_update(DATA));

    assert!(public_key
        .verify_digest(Sha1::new().chain_update(DATA), &signature)
        .is_ok());
}

#[test]
fn verify_validity() {
    let private_key = generate_keypair();
    let components = private_key.public_key().components();

    assert!(
        BigUint::zero() < *private_key.x() && private_key.x() < components.q(),
        "Requirement 0<x<q not met"
    );
    assert_eq!(
        *private_key.public_key().y(),
        components.g().modpow(private_key.x(), components.p()),
        "Requirement y=(g^x)%p not met"
    );
}
