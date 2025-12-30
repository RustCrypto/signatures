// We abused the deprecated attribute for unsecure key sizes
// But we want to use those small key sizes for fast tests
#![allow(deprecated)]
#![cfg(feature = "pkcs8")]

use dsa::VerifyingKey;
use pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};

#[cfg(feature = "hazmat")]
use {
    crypto_bigint::{
        BoxedUint, Odd,
        modular::{BoxedMontyForm, BoxedMontyParams},
    },
    dsa::{Components, KeySize, SigningKey},
    getrandom::rand_core::TryRngCore,
};

const OPENSSL_PEM_PUBLIC_KEY: &str = include_str!("pems/public.pem");

#[cfg(feature = "hazmat")]
fn generate_verifying_key() -> VerifyingKey {
    let mut rng = getrandom::SysRng.unwrap_err();
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

#[cfg(feature = "hazmat")]
#[test]
fn encode_decode_verifying_key() {
    let verifying_key = generate_verifying_key();
    let encoded_verifying_key = verifying_key.to_public_key_pem(LineEnding::LF).unwrap();
    let decoded_verifying_key = VerifyingKey::from_public_key_pem(&encoded_verifying_key).unwrap();

    assert_eq!(verifying_key, decoded_verifying_key);
}

#[cfg(feature = "hazmat")]
#[test]
fn validate_verifying_key() {
    let verifying_key = generate_verifying_key();
    let p = verifying_key.components().p();
    let q = verifying_key.components().q();

    let params = BoxedMontyParams::new(Odd::new((**p).clone()).unwrap());
    let form = BoxedMontyForm::new((**verifying_key.y()).clone(), params);

    // Taken from the parameter validation from bouncy castle
    assert_eq!(form.pow(q).retrieve(), BoxedUint::one());
}
