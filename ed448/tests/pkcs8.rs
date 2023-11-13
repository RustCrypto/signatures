//! PKCS#8 private key tests

#![cfg(feature = "pkcs8")]
use ed448_signature::pkcs8::{DecodePrivateKey, DecodePublicKey, KeypairBytes, PublicKeyBytes};
use hex_literal::hex;

#[cfg(feature = "alloc")]
use ed448_signature::pkcs8::{EncodePrivateKey, EncodePublicKey};

/// Ed448 PKCS#8 v1 private key encoded as ASN.1 DER.
const PKCS8_V1_DER: &[u8] = include_bytes!("examples/pkcs8-v1.der");

/// Ed448 SubjectPublicKeyInfo encoded as ASN.1 DER.
const PUBLIC_KEY_DER: &[u8] = include_bytes!("examples/pubkey.der");

#[test]
fn decode_pkcs8_v1() {
    let keypair = KeypairBytes::from_pkcs8_der(PKCS8_V1_DER).unwrap();

    // Extracted with:
    // $ openssl asn1parse -inform der -in tests/examples/pkcs8-v1.der
    assert_eq!(
        keypair.secret_key,
        &hex!("8A57471AA375074DC7D75EA2252E9933BB15C107E4F9A2F9CFEA6C418BEBB0774D1ABB671B58B96EFF95F35D63F2418422A59C7EAE3E00D70F")[..]
    );

    assert_eq!(keypair.public_key, None);
}

#[test]
fn decode_public_key() {
    let public_key = PublicKeyBytes::from_public_key_der(PUBLIC_KEY_DER).unwrap();

    // Extracted with:
    // $ openssl pkey -inform der -in tests/examples/pkcs8-v1.der -pubout -text
    assert_eq!(
        public_key.as_ref(),
        &hex!("f27f9809412035541b681c69fbe69b9d25a6af506d914ecef7d973fca04ccd33a8b96a0868211382ca08fe06b72e8c0cb3297f3a9d6bc02380")
    );
}

#[cfg(feature = "alloc")]
#[test]
fn encode_pkcs8_v1() {
    let pk = KeypairBytes::from_pkcs8_der(PKCS8_V1_DER).unwrap();
    let pk_der = pk.to_pkcs8_der().unwrap();
    assert_eq!(pk_der.as_bytes(), PKCS8_V1_DER);
}

#[cfg(feature = "alloc")]
#[test]
fn encode_public_key() {
    let pk = PublicKeyBytes::from_public_key_der(PUBLIC_KEY_DER).unwrap();
    let pk_der = pk.to_public_key_der().unwrap();
    assert_eq!(pk_der.as_ref(), PUBLIC_KEY_DER);
}
