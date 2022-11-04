// We abused the deprecated attribute for unsecure key sizes
// But we want to use those small key sizes for fast tests
#![allow(deprecated)]

use digest::Digest;
use dsa::{Components, KeySize, SigningKey};
use num_bigint::BigUint;
use num_traits::Zero;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use sha1::Sha1;
use signature::{DigestVerifier, RandomizedDigestSigner};

const OPENSSL_PEM_PRIVATE_KEY: &str = include_str!("pems/private.pem");

fn generate_keypair() -> SigningKey {
    let mut rng = rand::thread_rng();
    let components = Components::generate(&mut rng, KeySize::DSA_1024_160);
    SigningKey::generate(&mut rng, components)
}

#[test]
fn decode_encode_openssl_signing_key() {
    let signing_key = SigningKey::from_pkcs8_pem(OPENSSL_PEM_PRIVATE_KEY)
        .expect("Failed to decode PEM encoded OpenSSL key");

    let reencoded_signing_key = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode private key into PEM representation");

    assert_eq!(*reencoded_signing_key, OPENSSL_PEM_PRIVATE_KEY);
}

#[test]
fn encode_decode_signing_key() {
    let signing_key = generate_keypair();
    let encoded_signing_key = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let decoded_signing_key = SigningKey::from_pkcs8_pem(&encoded_signing_key).unwrap();

    assert_eq!(signing_key, decoded_signing_key);
}

#[test]
fn sign_and_verify() {
    const DATA: &[u8] = b"SIGN AND VERIFY THOSE BYTES";

    let signing_key = generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let signature =
        signing_key.sign_digest_with_rng(&mut rand::thread_rng(), Sha1::new().chain_update(DATA));

    assert!(verifying_key
        .verify_digest(Sha1::new().chain_update(DATA), &signature)
        .is_ok());
}

#[test]
fn verify_validity() {
    let signing_key = generate_keypair();
    let components = signing_key.verifying_key().components();

    assert!(
        BigUint::zero() < *signing_key.x() && signing_key.x() < components.q(),
        "Requirement 0<x<q not met"
    );
    assert_eq!(
        *signing_key.verifying_key().y(),
        components.g().modpow(signing_key.x(), components.p()),
        "Requirement y=(g^x)%p not met"
    );
}
